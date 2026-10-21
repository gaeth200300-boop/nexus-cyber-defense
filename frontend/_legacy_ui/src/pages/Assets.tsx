import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Modal, FieldError, EmptyState, Pagination } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, cn } from '../lib/utils';

export default function Assets() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const { projectId } = useUi();
  const [assets, setAssets] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const [showNew, setShowNew] = useState(params.get('new') === '1');
  const [newType, setNewType] = useState('domain');
  const [newValue, setNewValue] = useState('');
  const [newTags, setNewTags] = useState('');
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState('');
  const [detail, setDetail] = useState<any>(null);

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    api<{ items: any[]; total: number }>(`/projects/${projectId}/assets?q=${encodeURIComponent(q)}&limit=20&offset=${(page - 1) * 20}`)
      .then((d) => { setAssets(d.items); setTotal(d.total); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [projectId, q, page]); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async () => {
    if (!projectId) return;
    setCreating(true);
    setCreateErr('');
    try {
      await api(`/projects/${projectId}/assets`, {
        method: 'POST',
        body: JSON.stringify({ type: newType, value: newValue, tags: newTags.split(',').map((s) => s.trim()).filter(Boolean) }),
      });
      setShowNew(false);
      setNewValue('');
      load();
    } catch (e: any) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  };

  const openDetail = (id: string) => {
    api<any>(`/projects/${projectId}/assets/${id}`).then(setDetail).catch(() => {});
  };

  if (!projectId) return <Card><EmptyState title={t('selectProjectFirst')} /></Card>;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('assets')}</h1>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>◈ {t('addAsset')}</button>
      </div>

      <div className="flex gap-3 mb-4">
        <input className="form-input" style={{ maxWidth: 320 }} placeholder={t('search')} value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
      </div>

      {loading ? <Spinner /> : error ? <p style={{ color: 'var(--red)' }}>{error}</p> : assets.length === 0 ? (
        <Card><EmptyState icon="◈" title={t('noData')} desc="Add domains, IPs, or URLs within your authorized scope." /></Card>
      ) : (
        <Card>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>{t('value')}</th><th>{t('type')}</th><th>{t('risk')}</th><th>{t('openFindings')}</th><th>{t('lastScan')}</th><th>{t('state')}</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id} className="row-click" onClick={() => openDetail(a.id)}>
                    <td className="text-mono">{a.value}</td>
                    <td><Badge kind={a.type}>{a.type}</Badge></td>
                    <td><Badge kind={a.risk_severity || 'info'}>{a.risk_severity || '—'}</Badge></td>
                    <td className="font-bold">{a.open_findings}</td>
                    <td className="text-small text-muted">{fmtDate(a.last_scanned_at)}</td>
                    <td><Badge kind={a.state}>{a.state}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={20} total={total} onPage={setPage} />
        </Card>
      )}

      {showNew && (
        <Modal title={t('addAsset')} onClose={() => setShowNew(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={create} disabled={creating || !newValue.trim()}>{creating ? t('loading') : t('addAsset')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('assetType')}</label>
            <select className="form-select" value={newType} onChange={(e) => setNewType(e.target.value)}>
              <option value="domain">{t('domain')}</option>
              <option value="ip">{t('ip')}</option>
              <option value="url">{t('url')}</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">{t('value')}</label>
            <input className="form-input text-mono" value={newValue} onChange={(e) => setNewValue(e.target.value)} placeholder={newType === 'domain' ? 'example.com' : newType === 'ip' ? '192.168.1.1' : 'https://example.com'} dir="ltr" />
          </div>
          <div className="form-group">
            <label className="form-label">{t('tag')}</label>
            <input className="form-input" value={newTags} onChange={(e) => setNewTags(e.target.value)} placeholder="prod, web" />
          </div>
          {createErr && <FieldError message={createErr} />}
        </Modal>
      )}

      {detail && (
        <Modal title={detail.value} size="lg" onClose={() => setDetail(null)} footer={<button className="btn btn-secondary" onClick={() => setDetail(null)}>{t('close')}</button>}>
          <div className="grid-2">
            <div>
              <h4 className="mb-2">{t('asset')}</h4>
              <div className="text-small flex flex-col gap-1">
                <div><span className="text-muted">{t('type')}: </span>{detail.type}</div>
                <div><span className="text-muted">{t('state')}: </span>{detail.state}</div>
                <div><span className="text-muted">{t('risk')}: </span><Badge kind={detail.risk_severity || 'info'}>{detail.risk_severity || '—'}</Badge></div>
                <div><span className="text-muted">{t('monitored')}: </span>{detail.is_monitored ? t('yes') : t('no')}</div>
                <div><span className="text-muted">{t('firstSeen')}: </span>{fmtDate(detail.first_seen_at)}</div>
                <div><span className="text-muted">{t('lastSeen')}: </span>{fmtDate(detail.last_seen_at)}</div>
                <div><span className="text-muted">{t('lastScan')}: </span>{fmtDate(detail.last_scanned_at)}</div>
                <div><span className="text-muted">{t('source')}: </span>{detail.source || '—'}</div>
                <div><span className="text-muted">{t('tags')}: </span>{(detail.tags || []).join(', ') || '—'}</div>
              </div>
            </div>
            <div>
              <h4 className="mb-2">{t('services')} ({detail.services?.length || 0})</h4>
              {(detail.services || []).length === 0 && <div className="text-muted text-small">{t('noData')}</div>}
              {(detail.services || []).map((s: any) => (
                <div key={s.id} className="target-row">
                  <span className="target-status done" />
                  <div>
                    <div className="text-small font-bold">{s.name || 'unknown'} <span className="text-muted">:{s.port}</span></div>
                    <div className="text-small text-muted">{s.product} {s.version}</div>
                  </div>
                  <Badge kind={s.state}>{s.state}</Badge>
                </div>
              ))}
            </div>
          </div>
          {detail.changes?.length > 0 && (
            <>
              <h4 className="mt-4 mb-2">{t('changes')}</h4>
              {detail.changes.slice(0, 5).map((c: any) => (
                <div key={c.id} className="text-small flex gap-3 items-center">
                  <Badge kind={c.severity}>{c.severity}</Badge>
                  <span>{c.summary}</span>
                  <span className="text-muted">{fmtDate(c.detected_at)}</span>
                </div>
              ))}
            </>
          )}
        </Modal>
      )}
    </div>
  );
}
