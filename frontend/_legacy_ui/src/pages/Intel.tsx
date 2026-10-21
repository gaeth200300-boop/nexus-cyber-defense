import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, Pagination, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate } from '../lib/utils';

export default function Intel() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const { projectId } = useUi();
  const [tab, setTab] = useState<'cve' | 'kev' | 'links'>('cve');
  const [cveQ, setCveQ] = useState('');
  const [cveResults, setCveResults] = useState<any[]>([]);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState('');
  const [selectedCve, setSelectedCve] = useState<any>(null);

  const [kev, setKev] = useState<any[]>([]);
  const [kevTotal, setKevTotal] = useState(0);
  const [kevLoading, setKevLoading] = useState(false);
  const [kevError, setKevError] = useState('');
  const [kevPage, setKevPage] = useState(1);

  const [links, setLinks] = useState<any[]>([]);
  const [linksTotal, setLinksTotal] = useState(0);
  const [linksLoading, setLinksLoading] = useState(false);

  const searchCve = () => {
    setCveLoading(true);
    setCveError('');
    api<{ items: any[] }>(`/intel/search?q=${encodeURIComponent(cveQ)}&limit=20`)
      .then((d) => setCveResults(d.items))
      .catch((e) => setCveError(e.message))
      .finally(() => setCveLoading(false));
  };

  const loadKev = () => {
    setKevLoading(true);
    api<{ items: any[]; total: number }>(`/intel/kev?limit=25&offset=${(kevPage - 1) * 25}`)
      .then((d) => { setKev(d.items); setKevTotal(d.total); })
      .catch((e) => setKevError(e.message))
      .finally(() => setKevLoading(false));
  };

  useEffect(() => { if (tab === 'kev') loadKev(); }, [tab, kevPage]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadLinks = () => {
    if (!projectId) return;
    setLinksLoading(true);
    api<{ items: any[]; total: number }>(`/projects/${projectId}/intel/links?limit=25`)
      .then((d) => { setLinks(d.items); setLinksTotal(d.total); })
      .catch(() => {})
      .finally(() => setLinksLoading(false));
  };

  useEffect(() => { if (tab === 'links') loadLinks(); }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

  const syncKev = async () => {
    await api('/intel/kev/sync', { method: 'POST', body: JSON.stringify({}) });
    loadKev();
  };

  const correlate = async () => {
    if (!projectId) return;
    await api(`/projects/${projectId}/intel/correlate`, { method: 'POST', body: JSON.stringify({ max_cves: 50, include_kev: true }) });
    loadLinks();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('intel')}</h1>
        <div className="flex gap-2">
          {tab === 'kev' && <button className="btn btn-secondary btn-sm" onClick={syncKev}>↻ {t('syncKeV')}</button>}
          {tab === 'links' && <button className="btn btn-secondary btn-sm" onClick={correlate}>⚡ {t('correlateNow')}</button>}
        </div>
      </div>

      <div className="tabs">
        <button className={tab === 'cve' ? 'tab active' : 'tab'} onClick={() => setTab('cve')}>◉ {t('nvd')} / CVE</button>
        <button className={tab === 'kev' ? 'tab active' : 'tab'} onClick={() => setTab('kev')}>⬢ {t('kev')}</button>
        <button className={tab === 'links' ? 'tab active' : 'tab'} onClick={() => setTab('links')}>⛓ {t('correlation')}</button>
      </div>

      {tab === 'cve' && (
        <div>
          <div className="flex gap-3 mb-4">
            <input className="form-input" style={{ maxWidth: 400 }} placeholder={t('searchCvePlaceholder')} value={cveQ} onChange={(e) => setCveQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && searchCve()} dir="ltr" />
            <button className="btn btn-primary" onClick={searchCve} disabled={cveLoading}>{cveLoading ? t('loading') : t('cveSearch')}</button>
          </div>
          {cveError && <p style={{ color: 'var(--red)' }}>{cveError}</p>}
          {cveResults.length === 0 && !cveLoading && <Card><EmptyState icon="◉" title={t('noData')} desc={`${t('intelSources')}: NVD + CISA KEV`} /></Card>}
          {cveResults.length > 0 && (
            <div className="flex flex-col gap-2">
              {cveResults.map((c) => (
                <Card key={c.id} hover className="card-hover" >
                  <div className="flex items-center gap-3 cursor-pointer" onClick={() => setSelectedCve(c)}>
                    <span className="text-mono font-bold" style={{ color: 'var(--violet)' }}>{c.id}</span>
                    <span style={{ flex: 1 }}>{c.description?.slice(0, 140)}</span>
                    {c.cvss_v3_score != null && <Badge kind={c.cvss_severity || 'info'}>CVSS {c.cvss_v3_score}</Badge>}
                    {c.kev && <Badge kind="critical">{t('kev')}</Badge>}
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'kev' && (
        <div>
          {kevLoading ? <Spinner /> : kevError ? <p style={{ color: 'var(--red)' }}>{kevError}</p> : kev.length === 0 ? (
            <Card><EmptyState icon="⬢" title={t('noKev')} action={<button className="btn btn-primary mt-3" onClick={syncKev}>{t('syncKeV')}</button>} /></Card>
          ) : (
            <Card>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>CVE</th><th>{t('product')}</th><th>{t('vulnerabilityName')}</th><th>{t('dateAdded')}</th><th>{t('knownRansomware')}</th></tr></thead>
                  <tbody>
                    {kev.map((k) => (
                      <tr key={k.cve_id}>
                        <td className="text-mono">{k.cve_id}</td>
                        <td>{k.product}</td>
                        <td style={{ maxWidth: 320 }}>{k.vulnerability_name}</td>
                        <td className="text-small text-muted">{fmtDate(k.date_added)}</td>
                        <td>{k.known_ransomware ? <Badge kind="critical">Ransomware</Badge> : <span className="text-muted">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={kevPage} pageSize={25} total={kevTotal} onPage={setKevPage} />
            </Card>
          )}
        </div>
      )}

      {tab === 'links' && (
        <div>
          {linksLoading ? <Spinner /> : links.length === 0 ? (
            <Card><EmptyState icon="⛓" title={t('noLinks')} action={projectId ? <button className="btn btn-primary mt-3" onClick={correlate}>{t('correlateNow')}</button> : undefined} /></Card>
          ) : (
            <Card>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>CVE</th><th>{t('findingRef')}</th><th>{t('matchType')}</th><th>{t('rationale')}</th></tr></thead>
                  <tbody>
                    {links.map((l) => (
                      <tr key={l.id} className="row-click" onClick={() => nav(`/findings/${l.finding_id}`)}>
                        <td className="text-mono">{l.cve_id}</td>
                        <td className="text-small">{l.finding?.title?.slice(0, 60) || l.finding_id}</td>
                        <td><Badge kind={l.match_type}>{t(l.match_type)}</Badge></td>
                        <td className="text-small text-muted" style={{ maxWidth: 320 }}>{l.rationale}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={1} pageSize={25} total={linksTotal} onPage={() => {}} />
            </Card>
          )}
        </div>
      )}

      {selectedCve && (
        <CveDetail cve={selectedCve} onClose={() => setSelectedCve(null)} />
      )}
    </div>
  );
}

function CveDetail({ cve, onClose }: { cve: any; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="text-mono">{cve.id}</span>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <p className="mb-3">{cve.description}</p>
          <div className="grid-2 mb-3">
            <div className="text-small"><span className="text-muted">CVSS v3: </span><strong>{cve.cvss_v3_score || '—'}</strong></div>
            <div className="text-small"><span className="text-muted">CVSS v2: </span><strong>{cve.cvss_v2_score || '—'}</strong></div>
            <div className="text-small"><span className="text-muted">{t('publishedAt')}: </span>{fmtDate(cve.published_at)}</div>
            <div className="text-small"><span className="text-muted">{t('modifiedAt')}: </span>{fmtDate(cve.modified_at)}</div>
          </div>
          {cve.cwes?.length > 0 && <div className="mb-2"><span className="text-small font-bold">CWEs: </span>{cve.cwes.join(', ')}</div>}
          {cve.references?.length > 0 && (
            <div className="mb-2">
              <div className="text-small font-bold mb-1">{t('references')}:</div>
              {cve.references.slice(0, 5).map((r: any, i: number) => (
                <div key={i}><a href={r.url || r} target="_blank" rel="noreferrer" className="text-small">{r.title || r.url || r}</a></div>
              ))}
            </div>
          )}
          {cve.kev && (
            <div className="card mt-3" style={{ padding: 14 }}>
              <div className="font-bold mb-1" style={{ color: 'var(--red)' }}>⬢ CISA KEV</div>
              <div className="text-small">{cve.kev_detail?.short_description}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
