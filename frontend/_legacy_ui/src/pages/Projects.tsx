import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Modal, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate } from '../lib/utils';

export default function Projects() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const { projectId, setProjectId } = useUi();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showNew, setShowNew] = useState(params.get('new') === '1');
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [kind, setKind] = useState('assessment');
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState('');

  const load = () => {
    setLoading(true);
    api<{ items: any[] }>('/projects')
      .then((d) => { setProjects(d.items); if (!projectId && d.items.length) setProjectId(d.items[0].id); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    setCreating(true);
    setCreateErr('');
    try {
      const res = await api<any>('/projects', { method: 'POST', body: JSON.stringify({ name, description: desc, kind }) });
      setShowNew(false);
      setProjectId(res.project.id);
      load();
    } catch (e: any) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  };

  if (loading) return <Spinner label={t('loading')} />;
  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('projects')}</h1>
          <p className="text-muted text-small">{t('projectsDesc')}</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>▤ {t('newProject')}</button>
      </div>

      {projects.length === 0 ? (
        <Card>
          <div className="empty-state">
            <div className="empty-state-icon">▤</div>
            <div className="empty-state-title">{t('noProjects')}</div>
            <button className="btn btn-primary mt-3" onClick={() => setShowNew(true)}>{t('createFirst')}</button>
          </div>
        </Card>
      ) : (
        <div className="grid-3">
          {projects.map((p) => (
            <Card key={p.id} hover className="card-hover">
              <div className="flex items-center justify-between mb-2">
                <div className="font-bold" style={{ fontSize: 15 }}>{p.name}</div>
                <Badge kind={p.kind}>{t(p.kind)}</Badge>
              </div>
              <p className="text-muted text-small mb-3" style={{ minHeight: 32 }}>{p.description || '—'}</p>
              <div className="flex gap-4 text-small text-muted mb-3">
                <span>◈ {p.counts?.assets ?? 0} {t('assetsCount')}</span>
                <span>▶ {p.counts?.scans ?? 0} {t('scansCount')}</span>
                <span>⚠ {p.counts?.findings ?? 0} {t('findingsCount')}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-small text-muted">{t('createdAt')}: {fmtDate(p.created_at)}</span>
                <div className="flex gap-2">
                  <button className="btn btn-secondary btn-sm" onClick={() => setProjectId(p.id)}>{projectId === p.id ? t('active') : t('selectProject')}</button>
                  <button className="btn btn-primary btn-sm" onClick={() => { setProjectId(p.id); nav('/scans'); }}>{t('view')}</button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {showNew && (
        <Modal title={t('newProject')} onClose={() => setShowNew(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>{t('cancel_create')}</button>
            <button className="btn btn-primary" onClick={create} disabled={creating}>{creating ? t('loading') : t('createProject')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('projectName')}</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('projectDesc')}</label>
            <input className="form-input" value={desc} onChange={(e) => setDesc(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('projectKind')}</label>
            <select className="form-select" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="assessment">{t('assessment')}</option>
              <option value="monitoring">{t('monitoring')}</option>
            </select>
          </div>
          {createErr && <FieldError message={createErr} />}
        </Modal>
      )}
    </div>
  );
}
