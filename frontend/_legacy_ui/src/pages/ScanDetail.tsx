import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, openEventSource } from '../lib/api';
import { Card, Badge, Spinner, Progress } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, timeAgo, severityColor, cn } from '../lib/utils';

export default function ScanDetail() {
  const { t } = useTranslation();
  const { id } = useParams();
  const nav = useNavigate();
  const { projectId } = useUi();
  const [scan, setScan] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [error, setError] = useState('');
  const [streaming, setStreaming] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const eventsRef = useRef<HTMLDivElement>(null);

  const load = () => {
    api<any>(`/projects/${projectId}/scans/${id}`).then(setScan).catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    const interval = setInterval(() => {
      if (scan && (scan.status === 'running' || scan.status === 'queued')) load();
      else if (scan && scan.status !== 'running' && scan.status !== 'queued') clearInterval(interval);
    }, 5000);
    return () => clearInterval(interval);
  }, [projectId, id, scan?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!id) return;
    setStreaming(true);
    const es = openEventSource(
      `/projects/${projectId}/scans/${id}/stream`,
      (ev) => {
        if (ev.type === 'done') { setStreaming(false); return; }
        setEvents((prev) => [...prev.slice(-300), ev]);
      },
      () => setStreaming(false)
    );
    esRef.current = es;
    return () => { es.close(); esRef.current = null; };
  }, [projectId, id]);

  useEffect(() => {
    eventsRef.current?.scrollTo(0, eventsRef.current.scrollHeight);
  }, [events]);

  const cancel = async () => {
    await api(`/projects/${projectId}/scans/${id}/cancel`, { method: 'POST' });
    load();
  };

  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;
  if (!scan) return <Spinner label={t('loading')} />;

  const isActive = scan.status === 'running' || scan.status === 'queued';

  return (
    <div>
      <button className="btn btn-ghost btn-sm mb-3" onClick={() => nav('/scans')}>← {t('backToScans')}</button>
      <div className="flex items-center gap-3 mb-4" style={{ flexWrap: 'wrap' }}>
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{scan.name}</h1>
        <Badge kind={scan.status}>{t(scan.status)}</Badge>
        <Badge kind={scan.profile}>{t(scan.profile)}</Badge>
        {isActive && <button className="btn btn-danger btn-sm" onClick={cancel}>{t('cancel')}</button>}
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div>
          <Card title={t('scanProgress')} className="mb-4">
            <Progress value={scan.progress || 0} />
            <div className="flex justify-between mt-2 text-small text-muted">
              <span>{Math.round(scan.progress || 0)}%</span>
              <span>{t('phase')}: {scan.phase || '—'}</span>
            </div>
            <div className="divider" />
            <div className="text-small flex flex-col gap-1">
              <div><span className="text-muted">{t('engine')}: </span>{scan.engine || 'internal'} {scan.engine_version ? `v${scan.engine_version}` : ''}</div>
              <div><span className="text-muted">{t('startedAt')}: </span>{fmtDate(scan.started_at)}</div>
              <div><span className="text-muted">{t('finishedAt')}: </span>{fmtDate(scan.finished_at)}</div>
              <div><span className="text-muted">{t('targets')}: </span>{scan.target_count}</div>
            </div>
          </Card>

          <Card title={t('targets')} subtitle={t('scanTargets')}>
            {(scan.targets || []).map((tg: string, i: number) => (
              <div key={i} className="target-row">
                <span className={cn('target-status', scan.status === 'completed' ? 'done' : scan.status === 'failed' ? 'failed' : 'running')} />
                <span className="text-mono text-small">{tg}</span>
              </div>
            ))}
          </Card>
        </div>

        <div>
          <Card
            title={t('liveEvents')}
            subtitle={streaming ? t('live') : t('streamEnded')}
            actions={<button className="btn btn-secondary btn-sm" onClick={() => setEvents([])}>{t('reset')}</button>}
          >
            <div className="terminal" ref={eventsRef} style={{ height: 420 }}>
              {events.length === 0 && <div className="terminal-line t-info">等待事件… / waiting for events…</div>}
              {events.map((ev, i) => (
                <div key={i} className={cn('terminal-line', ev.kind === 'finding' ? 't-finding' : ev.level === 'error' ? 't-error' : ev.kind === 'progress' ? 't-progress' : ev.level === 'warn' ? 't-warn' : ev.kind === 'log' ? '' : 't-info')}>
                  <span className="t-time">[{timeAgo(ev.ts)}]</span>{' '}
                  {ev.kind === 'finding' && '⚠ '}{ev.message || JSON.stringify(ev.data || ev)}
                </div>
              ))}
              {streaming && <span className="terminal-caret" />}
            </div>
          </Card>
        </div>
      </div>

      {scan.stats && Object.keys(scan.stats).length > 0 && (
        <Card title={t('scanStats')} className="mt-4">
          <div className="flex gap-4" style={{ flexWrap: 'wrap' }}>
            {Object.entries(scan.stats).map(([k, v]) => (
              <div key={k} className="text-small">
                <span className="text-muted">{k}: </span>
                <strong>{String(v)}</strong>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
