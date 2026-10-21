import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Pagination } from '../components/ui';
import { fmtDateTime } from '../lib/utils';

export default function Audit() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);

  const load = () => {
    setLoading(true);
    api<{ items: any[]; total: number }>(`/audit?limit=25&offset=${(page - 1) * 25}`)
      .then((d) => { setEntries(d.items); setTotal(d.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(load, [page]);

  const verify = async () => {
    setVerifying(true);
    try {
      const res = await api<any>('/audit/verify?limit=1000');
      setVerifyResult(res);
    } catch { /* ignore */ } finally { setVerifying(false); }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('auditTitle')}</h1>
        <div className="flex gap-2">
          <button className="btn btn-secondary btn-sm" onClick={verify} disabled={verifying}>
            {verifying ? t('auditVerifyRunning') : t('verifyChain')}
          </button>
        </div>
      </div>

      {verifyResult && (
        <Card className="mb-4" style={{ borderColor: verifyResult.tampered ? 'var(--red)' : 'var(--green)' }}>
          <div className="flex items-center gap-3">
            <span style={{ fontSize: 20 }}>{verifyResult.tampered ? '⛔' : '✓'}</span>
            <div>
              <strong>{verifyResult.tampered ? t('chainBad') : t('chainOk')}</strong>
              <div className="text-small text-muted">{verifyResult.verified_count} {t('entriesCount')} · {verifyResult.verified_at ? fmtDateTime(verifyResult.verified_at) : ''}</div>
            </div>
          </div>
        </Card>
      )}

      {loading ? <Spinner /> : (
        <Card>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>{t('timeLabel')}</th><th>{t('actorLabel')}</th><th>{t('actionLabel')}</th><th>{t('entityLabel')}</th><th>{t('outcomeLabel')}</th><th>{t('ipLabel')}</th></tr></thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id}>
                    <td className="text-small text-muted whitespace-nowrap">{fmtDateTime(e.ts)}</td>
                    <td className="text-small">{e.actor_label || '—'}</td>
                    <td><Badge kind={e.outcome === 'success' ? 'enabled' : 'disabled'}>{e.action}</Badge></td>
                    <td className="text-small">{e.entity_type} {e.entity_id?.slice(0, 8) || ''}</td>
                    <td><Badge kind={e.outcome === 'success' ? 'success_outcome' : 'failure_outcome'}>{e.outcome}</Badge></td>
                    <td className="text-mono text-small">{e.ip || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={25} total={total} onPage={setPage} />
        </Card>
      )}
    </div>
  );
}
