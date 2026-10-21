import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Modal, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, severityColor } from '../lib/utils';

export default function FindingDetail() {
  const { t } = useTranslation();
  const { id } = useParams();
  const nav = useNavigate();
  const { projectId } = useUi();
  const [finding, setFinding] = useState<any>(null);
  const [error, setError] = useState('');
  const [showStatus, setShowStatus] = useState(false);
  const [newStatus, setNewStatus] = useState('');
  const [note, setNote] = useState('');
  const [showNote, setShowNote] = useState(false);
  const [noteText, setNoteText] = useState('');

  const load = () => {
    api<any>(`/projects/${projectId}/findings/${id}`)
      .then(setFinding)
      .catch((e) => setError(e.message));
  };

  useEffect(load, [projectId, id]);

  const setStatus = async () => {
    await api(`/projects/${projectId}/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus, triage_note: note || undefined }),
    });
    setShowStatus(false);
    load();
  };

  const addNote = async () => {
    await api(`/projects/${projectId}/findings/${id}/notes`, { method: 'POST', body: JSON.stringify({ note: noteText }) });
    setShowNote(false);
    setNoteText('');
    load();
  };

  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;
  if (!finding) return <Spinner label={t('loading')} />;

  return (
    <div>
      <button className="btn btn-ghost btn-sm mb-3" onClick={() => nav('/findings')}>← {t('back')}</button>

      <div className="flex items-center gap-3 mb-4" style={{ flexWrap: 'wrap' }}>
        <h1 style={{ fontSize: 18, fontWeight: 800, flex: 1, minWidth: 200 }}>{finding.title}</h1>
        <Badge kind={finding.severity}>{t(finding.severity)}</Badge>
        <Badge kind={finding.status}>{t(finding.status)}</Badge>
        <Badge kind={finding.confidence}>{t(finding.confidence)}</Badge>
        <button className="btn btn-secondary btn-sm" onClick={() => setShowStatus(true)}>{t('statusChange')}</button>
        <button className="btn btn-ghost btn-sm" onClick={() => setShowNote(true)}>{t('addNoteBtn')}</button>
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: '2fr 1fr' }}>
        <div>
          <Card title={t('description')} className="mb-4">
            <p style={{ fontSize: 13, lineHeight: 1.7 }}>{finding.description || '—'}</p>
          </Card>

          {finding.impact && (
            <Card title={t('impact')} className="mb-4">
              <p style={{ fontSize: 13 }}>{finding.impact}</p>
            </Card>
          )}

          <Card title={t('remediation')} className="mb-4">
            <p style={{ fontSize: 13 }}>{finding.remediation || '—'}</p>
          </Card>

          {finding.references?.length > 0 && (
            <Card title={t('references')}>
              <ul className="text-small flex flex-col gap-1">
                {finding.references.map((r: any, i: number) => (
                  <li key={i}><a href={r.url || r} target="_blank" rel="noreferrer">{r.title || r.url || r}</a></li>
                ))}
              </ul>
            </Card>
          )}

          {finding.evidence?.length > 0 && (
            <Card title={t('evidenceSection')} subtitle={t('evidence_redacted')} className="mt-4">
              {finding.evidence.map((ev: any) => (
                <div key={ev.id} className="mb-4" style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: 14 }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Badge kind="info">{ev.kind}</Badge>
                    <span className="text-small text-muted">{ev.label}</span>
                    {ev.redacted && <Badge kind="low">{t('redactedNote')}</Badge>}
                  </div>
                  {ev.headers && (
                    <div className="mb-2">
                      <div className="text-small font-bold mb-1">{t('headersLabel')}</div>
                      <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 8, borderRadius: 6, overflow: 'auto', maxHeight: 120 }}>{JSON.stringify(ev.headers, null, 2)}</pre>
                    </div>
                  )}
                  {ev.request_snippet && (
                    <div className="mb-2">
                      <div className="text-small font-bold mb-1">{t('requestSnippet')}</div>
                      <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 8, borderRadius: 6, overflow: 'auto', maxHeight: 120 }}>{ev.request_snippet}</pre>
                    </div>
                  )}
                  {ev.response_snippet && (
                    <div className="mb-2">
                      <div className="text-small font-bold mb-1">{t('responseSnippet')}</div>
                      <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 8, borderRadius: 6, overflow: 'auto', maxHeight: 120 }}>{ev.response_snippet}</pre>
                    </div>
                  )}
                  {ev.body_excerpt && (
                    <div>
                      <div className="text-small font-bold mb-1">{t('bodyExcerpt')}</div>
                      <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 8, borderRadius: 6, overflow: 'auto', maxHeight: 100 }}>{ev.body_excerpt}</pre>
                    </div>
                  )}
                  {ev.raw_sha256 && <div className="text-small text-muted mt-2">{t('rawHashLabel')}: <span className="text-mono">{ev.raw_sha256.slice(0, 16)}…</span></div>}
                </div>
              ))}
            </Card>
          )}
        </div>

        <div>
          <Card className="mb-4">
            <div className="text-small flex flex-col gap-2">
              <div className="flex justify-between"><span className="text-muted">{t('affectedAsset')}</span><strong>{finding.asset?.value || '—'}</strong></div>
              <div className="flex justify-between"><span className="text-muted">{t('affectedService')}</span><strong>{finding.service?.name || '—'}</strong></div>
              <div className="flex justify-between"><span className="text-muted">{t('category')}</span><span>{finding.category}</span></div>
              {finding.cve && <div className="flex justify-between"><span className="text-muted">CVE</span><span className="text-mono">{finding.cve}</span></div>}
              {finding.cwe && <div className="flex justify-between"><span className="text-muted">CWE</span><span>{finding.cwe}</span></div>}
              {finding.owasp && <div className="flex justify-between"><span className="text-muted">OWASP</span><span>{finding.owasp}</span></div>}
              {finding.cvss_score != null && <div className="flex justify-between"><span className="text-muted">CVSS</span><strong>{finding.cvss_score}</strong></div>}
              <div className="flex justify-between"><span className="text-muted">{t('firstDetected')}</span><span>{fmtDate(finding.first_seen_at)}</span></div>
              <div className="flex justify-between"><span className="text-muted">{t('lastSeen')}</span><span>{fmtDate(finding.last_seen_at)}</span></div>
              <div className="flex justify-between"><span className="text-muted">{t('occurrenceCount')}</span><span>{finding.occurrence_count}</span></div>
              <div className="flex justify-between"><span className="text-muted">{t('detectedBy')}</span><span className="text-mono text-small">{finding.engine_version || '—'}</span></div>
            </div>
          </Card>

          {finding.intel?.length > 0 && (
            <Card title={t('intel')} className="mb-4">
              {finding.intel.map((l: any) => (
                <div key={l.id} className="target-row">
                  <div>
                    <div className="text-mono text-small font-bold">{l.cve_id}</div>
                    <div className="text-small text-muted">{l.rationale}</div>
                  </div>
                  <Badge kind={l.match_type}>{t(l.match_type)}</Badge>
                </div>
              ))}
            </Card>
          )}

          {finding.timeline?.length > 0 && (
            <Card title={t('statusHistory')}>
              {finding.timeline.map((ev: any, i: number) => (
                <div key={i} className="target-row">
                  <div>
                    <div className="text-small">
                      {ev.from_status && <Badge kind={ev.from_status}>{t(ev.from_status)}</Badge>}
                      {ev.from_status && ' → '}
                      <Badge kind={ev.to_status}>{t(ev.to_status)}</Badge>
                    </div>
                    <div className="text-small text-muted">{ev.actor_label || 'system'} · {fmtDate(ev.ts)}</div>
                  </div>
                </div>
              ))}
            </Card>
          )}
        </div>
      </div>

      {showStatus && (
        <Modal title={t('statusChange')} onClose={() => setShowStatus(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowStatus(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={setStatus}>{t('saveChanges')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('newStatus')}</label>
            <select className="form-select" value={newStatus || finding.status} onChange={(e) => setNewStatus(e.target.value)}>
              {['open', 'confirmed', 'fixed', 'accepted_risk', 'false_positive'].map((s) => <option key={s} value={s}>{t(s)}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">{t('triageNote')}</label>
            <input className="form-input" value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
        </Modal>
      )}

      {showNote && (
        <Modal title={t('addNote')} onClose={() => setShowNote(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNote(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={addNote}>{t('addNoteBtn')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('note')}</label>
            <textarea className="form-textarea" value={noteText} onChange={(e) => setNoteText(e.target.value)} rows={3} />
          </div>
        </Modal>
      )}
    </div>
  );
}
