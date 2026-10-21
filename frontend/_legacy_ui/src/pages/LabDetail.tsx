import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, ConfirmDialog } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate } from '../lib/utils';

export default function LabDetail() {
  const { t } = useTranslation();
  const { id } = useParams();
  const nav = useNavigate();
  const { projectId } = useUi();
  const [lab, setLab] = useState<any>(null);
  const [run, setRun] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [showReset, setShowReset] = useState(false);
  const [hintsUsed, setHintsUsed] = useState(0);

  const load = () => {
    api<any>(`/labs/${id}`).then((d) => {
      setLab(d.lab);
      setRun(d.run);
      if (d.run?.hints_used) setHintsUsed(d.run.hints_used.length);
    }).catch((e) => setError(e.message)).finally(() => setLoading(false));
  };

  useEffect(load, [id]);

  const start = async () => {
    await api(`/labs/${id}/start`, { method: 'POST', body: JSON.stringify({ project_id: projectId }) });
    load();
  };

  const submit = async () => {
    await api(`/labs/runs/${run.id}/submit`, { method: 'POST', body: JSON.stringify({ answers }) });
    load();
  };

  const hint = async () => {
    const res = await api<any>(`/labs/runs/${run.id}/hint`, { method: 'POST' });
    setHintsUsed(res.run.hints_used?.length || hintsUsed + 1);
  };

  const reset = async () => {
    await api(`/labs/runs/${run.id}/reset`, { method: 'POST' });
    setShowReset(false);
    load();
  };

  if (loading) return <Spinner />;
  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;
  if (!lab) return null;

  const isFinished = run?.status === 'finished';
  const checks = lab.checks || [];

  return (
    <div>
      <button className="btn btn-ghost btn-sm mb-3" onClick={() => nav('/labs')}>← {t('back')}</button>
      <div className="flex items-center gap-3 mb-4" style={{ flexWrap: 'wrap' }}>
        <h1 style={{ fontSize: 20, fontWeight: 800, flex: 1, minWidth: 200 }}>{lab.title_ar || lab.title_en}</h1>
        <Badge kind={lab.level}>{t(lab.level)}</Badge>
        <Badge kind="info">★ {lab.points} {t('points')}</Badge>
        {lab.requires_private_access && <Badge kind="critical">🔒 {t('isolated')}</Badge>}
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: '1fr 1.4fr' }}>
        <div>
          <Card title={t('labInstructions')} className="mb-4">
            <p className="text-small" style={{ lineHeight: 1.7 }}>{lab.description_ar || lab.description_en}</p>
          </Card>

          {lab.objectives?.length > 0 && (
            <Card title={t('objectives')} className="mb-4">
              {lab.objectives.map((o: string, i: number) => (
                <div key={i} className="text-small flex gap-2 items-center mb-1">
                  <span style={{ color: 'var(--cyan)' }}>◈</span> {o}
                </div>
              ))}
            </Card>
          )}

          <Card title={t('resourceLimits')}>
            <div className="text-small flex flex-col gap-1">
              <div>{t('timeLimit')}: {lab.resource_limits?.time_minutes || '—'} {t('minutes')}</div>
              <div>{t('networkIsolated')}: {lab.requires_private_access ? t('yes_isolated') : t('no_isolated')}</div>
            </div>
          </Card>
        </div>

        <div>
          {!run && (
            <Card>
              <EmptyState icon="⚗" title={t('startChallenge')} />
              <button className="btn btn-primary btn-block mt-3" onClick={start}>{t('startLab')}</button>
            </Card>
          )}

          {run && !isFinished && (
            <Card
              title={t('activeRun')}
              actions={
                <div className="flex gap-2">
                  <button className="btn btn-ghost btn-sm" onClick={hint} disabled={hintsUsed >= (lab.hints_total || 3)}>{t('showHint')} ({lab.hints_total - hintsUsed})</button>
                  <button className="btn btn-danger btn-sm" onClick={() => setShowReset(true)}>{t('resetLab')}</button>
                </div>
              }
            >
              <div className="text-small text-muted mb-3">{t('attempts')}: {run.attempts} · {t('hintsUsed')}: {hintsUsed}</div>

              {checks.map((c: any, i: number) => (
                <div key={i} className="form-group">
                  <label className="form-label">{c.question || c.name}</label>
                  <input
                    className="form-input text-mono"
                    value={answers[c.id || i] || ''}
                    onChange={(e) => setAnswers({ ...answers, [c.id || i]: e.target.value })}
                    placeholder={t('flagFormat')}
                    dir="ltr"
                  />
                </div>
              ))}

              <button className="btn btn-primary btn-block" onClick={submit}>{t('submitAnswers')}</button>
            </Card>
          )}

          {run && isFinished && (
            <Card title={t('labComplete')}>
              <div className="text-center mb-4">
                <div style={{ fontSize: 40 }}>🏆</div>
                <div className="font-bold text-lg">{t('perfectScore')}</div>
                <div className="text-muted">{t('finalScore')}: {run.score}/{lab.max_points}</div>
              </div>
              {(run.checks_result || []).map((c: any, i: number) => (
                <div key={i} className="target-row">
                  <Badge kind={c.passed ? 'passed' : 'failed'}>{c.passed ? t('passed') : t('failed')}</Badge>
                  <div style={{ flex: 1 }}>
                    <div className="text-small font-bold">{c.name || c.question}</div>
                    {c.explanation && <div className="text-small text-muted">{c.explanation}</div>}
                  </div>
                </div>
              ))}
              <button className="btn btn-secondary btn-block mt-4" onClick={() => nav('/labs')}>{t('viewLeaderboard')}</button>
            </Card>
          )}

          {run && run.checks_result && !isFinished && (
            <Card title={t('checks')} className="mt-4">
              {run.checks_result.map((c: any, i: number) => (
                <div key={i} className="target-row">
                  <Badge kind={c.passed ? 'passed' : 'failed'}>{c.passed ? t('passed') : t('failed')}</Badge>
                  <span className="text-small">{c.name}</span>
                </div>
              ))}
            </Card>
          )}
        </div>
      </div>

      {showReset && (
        <ConfirmDialog title={t('resetLab')} message={t('resetConfirm')} onConfirm={reset} onCancel={() => setShowReset(false)} danger />
      )}
    </div>
  );
}
