import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, downloadFile } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, Modal, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, fmtBytes } from '../lib/utils';

export default function Reports() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const { projectId } = useUi();
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showNew, setShowNew] = useState(params.get('new') === '1');
  const [title, setTitle] = useState('');
  const [kind, setKind] = useState('executive');
  const [format, setFormat] = useState('pdf');
  const [periodFrom, setPeriodFrom] = useState('');
  const [periodTo, setPeriodTo] = useState('');
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState('');

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    api<{ items: any[] }>(`/projects/${projectId}/reports?limit=50`)
      .then((d) => setReports(d.items))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [projectId]);

  const create = async () => {
    if (!projectId) return;
    setCreating(true);
    setCreateErr('');
    try {
      await api(`/projects/${projectId}/reports`, {
        method: 'POST',
        body: JSON.stringify({
          title: title || `${t(kind)} report`,
          kind, format,
          period_from: periodFrom || undefined,
          period_to: periodTo || undefined,
        }),
      });
      setShowNew(false);
      load();
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
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('reports')}</h1>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>▧ {t('newReport')}</button>
      </div>

      {loading ? <Spinner /> : error ? <p style={{ color: 'var(--red)' }}>{error}</p> : reports.length === 0 ? (
        <Card><EmptyState icon="▧" title={t('noData')} action={<button className="btn btn-primary mt-3" onClick={() => setShowNew(true)}>{t('newReport')}</button>} /></Card>
      ) : (
        <div className="flex flex-col gap-3">
          {reports.map((r) => (
            <Card key={r.id} hover className="card-hover">
              <div className="flex items-center gap-4" style={{ flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div className="flex items-center gap-2">
                    <span className="font-bold">{r.title}</span>
                    <Badge kind={r.kind}>{t(r.kind)}</Badge>
                    <Badge kind={r.format}>{r.format.toUpperCase()}</Badge>
                    <Badge kind={r.status}>{t(r.status)}</Badge>
                  </div>
                  <div className="text-small text-muted mt-1">
                    {fmtDate(r.created_at)} · {fmtBytes(r.size_bytes)} · {t('generatedBy')}: {r.created_by || 'system'}
                  </div>
                </div>
                <div className="flex gap-2">
                  {r.status === 'completed' && (
                    <button className="btn btn-secondary btn-sm" onClick={() => downloadFile(`/projects/${projectId}/reports/${r.id}/download`, `${r.title}.${r.format}`)}>
                      ⬇ {t('download')}
                    </button>
                  )}
                  <button className="btn btn-ghost btn-sm" onClick={() => api(`/projects/${projectId}/reports/${r.id}/regenerate`, { method: 'POST' }).then(load)}>
                    ↻ {t('regenerate')}
                  </button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {showNew && (
        <Modal title={t('newReport')} onClose={() => setShowNew(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={create} disabled={creating}>{creating ? t('generating') : t('generate')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('reportTitle')}</label>
            <input className="form-input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder={`${t(kind)} report`} />
          </div>
          <div className="grid-2">
            <div className="form-group">
              <label className="form-label">{t('reportKind')}</label>
              <select className="form-select" value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="executive">{t('executive')}</option>
                <option value="technical">{t('technical')}</option>
                <option value="full">{t('fullReport')}</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">{t('reportFormat')}</label>
              <select className="form-select" value={format} onChange={(e) => setFormat(e.target.value)}>
                <option value="pdf">PDF</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
              </select>
            </div>
          </div>
          <div className="grid-2">
            <div className="form-group">
              <label className="form-label">{t('periodFrom')}</label>
              <input className="form-input" type="date" value={periodFrom} onChange={(e) => setPeriodFrom(e.target.value)} dir="ltr" />
            </div>
            <div className="form-group">
              <label className="form-label">{t('periodTo')}</label>
              <input className="form-input" type="date" value={periodTo} onChange={(e) => setPeriodTo(e.target.value)} dir="ltr" />
            </div>
          </div>
          {createErr && <FieldError message={createErr} />}
        </Modal>
      )}
    </div>
  );
}
