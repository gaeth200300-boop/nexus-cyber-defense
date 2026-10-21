import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, downloadFile } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, Pagination, Modal, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, cn, toCsv, downloadBlob } from '../lib/utils';

export default function Findings() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const { projectId } = useUi();
  const [findings, setFindings] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('');
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showBulk, setShowBulk] = useState(false);
  const [bulkAction, setBulkAction] = useState('status');
  const [bulkStatus, setBulkStatus] = useState('fixed');
  const [bulkNote, setBulkNote] = useState('');

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (sev) params.set('severity', sev);
    if (status) params.set('status', status);
    params.set('limit', '25');
    params.set('offset', String((page - 1) * 25));
    api<{ items: any[]; total: number }>(`/projects/${projectId}/findings?${params}`)
      .then((d) => { setFindings(d.items); setTotal(d.total); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [projectId, q, sev, status, page]);

  const exportCsv = () => {
    const csv = toCsv(findings, [
      { key: 'title', label: 'Title' },
      { key: 'severity', label: 'Severity' },
      { key: 'status', label: 'Status' },
      { key: 'category', label: 'Category' },
      { key: 'cve', label: 'CVE' },
      { key: 'first_seen_at', label: 'First Seen' },
    ]);
    downloadBlob(new Blob([csv], { type: 'text/csv' }), 'findings.csv');
  };

  const bulk = async () => {
    const ids = Array.from(selected);
    await api(`/projects/${projectId}/findings/bulk`, {
      method: 'POST',
      body: JSON.stringify({ ids, action: bulkAction, status: bulkAction === 'status' ? bulkStatus : undefined, note: bulkNote || undefined }),
    });
    setShowBulk(false);
    setSelected(new Set());
    load();
  };

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelected(next);
  };

  if (!projectId) return <Card><EmptyState title={t('selectProjectFirst')} /></Card>;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('findings')}</h1>
        <div className="flex gap-2">
          <button className="btn btn-secondary btn-sm" onClick={exportCsv}>{t('exportCsv')}</button>
          {selected.size > 0 && <button className="btn btn-primary btn-sm" onClick={() => setShowBulk(true)}>{t('bulkUpdate')} ({selected.size})</button>}
        </div>
      </div>

      <div className="flex gap-3 mb-4" style={{ flexWrap: 'wrap' }}>
        <input className="form-input" style={{ maxWidth: 240 }} placeholder={t('searchFindings')} value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        <select className="form-select" style={{ maxWidth: 140 }} value={sev} onChange={(e) => { setSev(e.target.value); setPage(1); }}>
          <option value="">{t('all')} {t('severity')}</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{t(s)}</option>)}
        </select>
        <select className="form-select" style={{ maxWidth: 160 }} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
          <option value="">{t('all')} {t('status')}</option>
          {['open', 'confirmed', 'fixed', 'accepted_risk', 'false_positive'].map((s) => <option key={s} value={s}>{t(s)}</option>)}
        </select>
      </div>

      {loading ? <Spinner /> : error ? <p style={{ color: 'var(--red)' }}>{error}</p> : findings.length === 0 ? (
        <Card><EmptyState icon="⚠" title={t('noFindings')} desc={t('findingsHint')} /></Card>
      ) : (
        <Card>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}><input type="checkbox" onChange={(e) => {
                    if (e.target.checked) setSelected(new Set(findings.map((f) => f.id)));
                    else setSelected(new Set());
                  }} /></th>
                  <th>{t('findingRow')}</th>
                  <th>{t('severityCol')}</th>
                  <th>{t('statusCol')}</th>
                  <th>{t('confidenceCol')}</th>
                  <th>{t('categoryCol')}</th>
                  <th>{t('cveCol')}</th>
                  <th>{t('firstSeenCol')}</th>
                  <th>{t('actionsCol')}</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="row-click" onClick={() => nav(`/findings/${f.id}`)}>
                    <td><input type="checkbox" checked={selected.has(f.id)} onChange={() => toggle(f.id)} onClick={(e) => e.stopPropagation()} /></td>
                    <td style={{ maxWidth: 280 }}>
                      <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                      <div className="text-small text-muted text-mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.target || f.location || ''}</div>
                    </td>
                    <td><Badge kind={f.severity}>{t(f.severity)}</Badge></td>
                    <td><Badge kind={f.status}>{t(f.status)}</Badge></td>
                    <td><Badge kind={f.confidence}>{t(f.confidence)}</Badge></td>
                    <td className="text-small">{f.category}</td>
                    <td className="text-mono text-small">{f.cve || '—'}</td>
                    <td className="text-small text-muted">{fmtDate(f.first_seen_at)}</td>
                    <td>
                      {f.status !== 'fixed' && <button className="btn btn-ghost btn-sm" onClick={(e) => { e.stopPropagation(); nav(`/findings/${f.id}`); }}>{t('triage')}</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={25} total={total} onPage={setPage} />
        </Card>
      )}

      {showBulk && (
        <Modal title={`${t('bulkUpdate')} (${selected.size})`} onClose={() => setShowBulk(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowBulk(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={bulk}>{t('apply')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('bulkAction')}</label>
            <select className="form-select" value={bulkAction} onChange={(e) => setBulkAction(e.target.value)}>
              <option value="status">{t('statusChange')}</option>
              <option value="assign">{t('assign')}</option>
            </select>
          </div>
          {bulkAction === 'status' && (
            <div className="form-group">
              <label className="form-label">{t('toStatus')}</label>
              <select className="form-select" value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)}>
                {['fixed', 'accepted_risk', 'false_positive', 'open'].map((s) => <option key={s} value={s}>{t(s)}</option>)}
              </select>
            </div>
          )}
          <div className="form-group">
            <label className="form-label">{t('note')}</label>
            <input className="form-input" value={bulkNote} onChange={(e) => setBulkNote(e.target.value)} />
          </div>
        </Modal>
      )}
    </div>
  );
}
