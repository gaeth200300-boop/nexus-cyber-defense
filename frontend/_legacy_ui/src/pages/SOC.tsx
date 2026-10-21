import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, apiUpload } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, Pagination, Modal, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate } from '../lib/utils';

export default function SOC() {
  const { t } = useTranslation();
  const { projectId } = useUi();
  const [tab, setTab] = useState<'events' | 'alerts' | 'incidents' | 'rules'>('events');
  const [events, setEvents] = useState<any[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [alertDetail, setAlertDetail] = useState<any>(null);
  const [incidentDetail, setIncidentDetail] = useState<any>(null);
  const [showRule, setShowRule] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [ruleSeverity, setRuleSeverity] = useState('medium');
  const [ruleDef, setRuleDef] = useState('{\n  "event_type": "auth_failure",\n  "threshold": 5\n}');
  const [ruleErr, setRuleErr] = useState('');

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    Promise.all([
      api<{ items: any[]; total: number }>(`/projects/${projectId}/soc/events?limit=25&offset=${(page - 1) * 25}`),
      api<{ items: any[] }>(`/projects/${projectId}/soc/alerts?limit=25`),
      api<{ items: any[] }>(`/projects/${projectId}/soc/incidents?limit=25`),
      api<{ items: any[] }>(`/projects/${projectId}/soc/rules`),
    ]).then(([ev, al, inc, rl]) => {
      setEvents(ev.items); setEventsTotal(ev.total);
      setAlerts(al.items); setIncidents(inc.items); setRules(rl.items);
    }).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, [projectId, page]); // eslint-disable-line react-hooks/exhaustive-deps

  const uploadLogs = async (file: File) => {
    if (!projectId) return;
    await apiUpload(`/projects/${projectId}/soc/sources`, file, { name: file.name, format: 'auto' });
    load();
  };

  const createRule = async () => {
    setRuleErr('');
    try {
      JSON.parse(ruleDef);
      await api(`/projects/${projectId}/soc/rules`, {
        method: 'POST',
        body: JSON.stringify({ name: ruleName, severity: ruleSeverity, definition: JSON.parse(ruleDef) }),
      });
      setShowRule(false);
      load();
    } catch (e: any) {
      setRuleErr(e instanceof SyntaxError ? 'Invalid JSON' : e.message);
    }
  };

  const uploadInput = React.createRef<HTMLInputElement>();

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('soc')}</h1>
        <div className="flex gap-2">
          <input ref={uploadInput} type="file" accept=".log,.json,.csv,.txt" style={{ display: 'none' }} onChange={(e) => { const f = e.target.files?.[0]; if (f) uploadLogs(f); }} />
          <button className="btn btn-secondary btn-sm" onClick={() => uploadInput.current?.click()}>⇪ {t('uploadLogs')}</button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowRule(true)}>+ {t('newRule')}</button>
        </div>
      </div>

      <div className="tabs">
        <button className={tab === 'events' ? 'tab active' : 'tab'} onClick={() => setTab('events')}>{t('logEvents')} ({eventsTotal})</button>
        <button className={tab === 'alerts' ? 'tab active' : 'tab'} onClick={() => setTab('alerts')}>{t('alerts')} ({alerts.length})</button>
        <button className={tab === 'incidents' ? 'tab active' : 'tab'} onClick={() => setTab('incidents')}>{t('incidents')} ({incidents.length})</button>
        <button className={tab === 'rules' ? 'tab active' : 'tab'} onClick={() => setTab('rules')}>{t('detectionRules')} ({rules.length})</button>
      </div>

      {loading ? <Spinner /> : (
        <>
          {tab === 'events' && (
            <Card>
              {events.length === 0 ? <EmptyState icon="◍" title={t('noEvents')} desc="Upload logs to populate the event stream." /> : (
                <>
                  <div className="table-wrap">
                    <table className="table">
                      <thead><tr><th>{t('timestamp')}</th><th>{t('severity')}</th><th>{t('eventType')}</th><th>{t('srcIp')}</th><th>{t('message')}</th></tr></thead>
                      <tbody>
                        {events.map((e) => (
                          <tr key={e.id}>
                            <td className="text-small text-muted whitespace-nowrap">{fmtDate(e.ts)}</td>
                            <td><Badge kind={e.severity}>{e.severity}</Badge></td>
                            <td className="text-small">{e.event_type}</td>
                            <td className="text-mono text-small">{e.src_ip || '—'}</td>
                            <td className="text-small" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination page={page} pageSize={25} total={eventsTotal} onPage={setPage} />
                </>
              )}
            </Card>
          )}

          {tab === 'alerts' && (
            <div className="flex flex-col gap-3">
              {alerts.length === 0 && <Card><EmptyState icon="⚠" title={t('noData')} /></Card>}
              {alerts.map((a) => (
                <Card key={a.id} hover className="card-hover">
                  <div className="flex items-center gap-3 cursor-pointer" onClick={() => setAlertDetail(a)}>
                    <div style={{ flex: 1 }}>
                      <div className="flex items-center gap-2">
                        <Badge kind={a.severity}>{t(a.severity)}</Badge>
                        <Badge kind={a.status}>{a.status}</Badge>
                        <strong>{a.title}</strong>
                      </div>
                      <div className="text-small text-muted mt-1">{a.description}</div>
                      <div className="text-small text-muted">{a.event_count} {t('alertEvents')} · {fmtDate(a.first_seen_at)}</div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {tab === 'incidents' && (
            <div className="flex flex-col gap-3">
              {incidents.length === 0 && <Card><EmptyState icon="◍" title={t('noIncidents')} /></Card>}
              {incidents.map((inc) => (
                <Card key={inc.id} hover className="card-hover">
                  <div className="flex items-center gap-3 cursor-pointer" onClick={() => setIncidentDetail(inc)}>
                    <div style={{ flex: 1 }}>
                      <div className="flex items-center gap-2">
                        <Badge kind={inc.severity}>{t(inc.severity)}</Badge>
                        <Badge kind={inc.status}>{t(inc.status)}</Badge>
                        <strong>{inc.title}</strong>
                      </div>
                      <div className="text-small text-muted">{inc.summary}</div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {tab === 'rules' && (
            <div className="flex flex-col gap-3">
              {rules.map((r) => (
                <Card key={r.id}>
                  <div className="flex items-center gap-3">
                    <div style={{ flex: 1 }}>
                      <div className="flex items-center gap-2">
                        <strong>{r.name}</strong>
                        <Badge kind={r.severity}>{t(r.severity)}</Badge>
                        <Badge kind={r.enabled ? 'enabled' : 'disabled'}>{r.enabled ? t('enabled') : t('disabled')}</Badge>
                        <Badge kind="info">{r.is_builtin ? t('builtin') : t('custom')}</Badge>
                      </div>
                      <div className="text-small text-muted">{r.description}</div>
                      <div className="text-small text-muted">{t('triggerCount')}: {r.trigger_count} · {t('lastTriggered')}: {fmtDate(r.last_triggered_at)}</div>
                    </div>
                  </div>
                  <details className="mt-2">
                    <summary className="text-small cursor-pointer">{t('ruleDefinition')}</summary>
                    <pre className="text-mono text-small mt-2" style={{ background: 'var(--bg-2)', padding: 10, borderRadius: 6, overflow: 'auto' }}>{JSON.stringify(r.definition, null, 2)}</pre>
                  </details>
                </Card>
              ))}
            </div>
          )}
        </>
      )}

      {alertDetail && (
        <Modal title={alertDetail.title} onClose={() => setAlertDetail(null)} footer={<button className="btn btn-secondary" onClick={() => setAlertDetail(null)}>{t('close')}</button>}>
          <div className="flex gap-2 mb-3">
            <Badge kind={alertDetail.severity}>{t(alertDetail.severity)}</Badge>
            <Badge kind={alertDetail.status}>{alertDetail.status}</Badge>
          </div>
          <p className="text-small mb-3">{alertDetail.description}</p>
          <div className="text-small"><span className="text-muted">{t('alertEvents')}: </span>{alertDetail.event_count}</div>
          {alertDetail.meta && <pre className="text-mono text-small mt-3" style={{ background: 'var(--bg-2)', padding: 10, borderRadius: 6, overflow: 'auto' }}>{JSON.stringify(alertDetail.meta, null, 2)}</pre>}
        </Modal>
      )}

      {showRule && (
        <Modal title={t('newRule')} onClose={() => setShowRule(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowRule(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={createRule}>{t('createRule')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('ruleName')}</label>
            <input className="form-input" value={ruleName} onChange={(e) => setRuleName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('ruleSeverity')}</label>
            <select className="form-select" value={ruleSeverity} onChange={(e) => setRuleSeverity(e.target.value)}>
              {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{t(s)}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">{t('jsonDSL')}</label>
            <textarea className="form-textarea text-mono" value={ruleDef} onChange={(e) => setRuleDef(e.target.value)} rows={6} dir="ltr" />
          </div>
          {ruleErr && <FieldError message={ruleErr} />}
        </Modal>
      )}
    </div>
  );
}
