import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, apiUpload } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, FieldError } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtBytes } from '../lib/utils';

export default function Network() {
  const { t } = useTranslation();
  const { projectId } = useUi();
  const [tab, setTab] = useState<'scan' | 'diag' | 'pcap'>('scan');

  // port scan state
  const [host, setHost] = useState('');
  const [portRange, setPortRange] = useState('common');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanError, setScanError] = useState('');

  // pcap state
  const [pcapResult, setPcapResult] = useState<any>(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [pcapError, setPcapError] = useState('');

  const runPortScan = async () => {
    if (!projectId || !host.trim()) return;
    setScanning(true);
    setScanError('');
    setScanResult(null);
    try {
      const res = await api<any>(`/projects/${projectId}/scans`, {
        method: 'POST',
        body: JSON.stringify({
          name: `Port scan ${host}`,
          kind: 'network',
          profile: 'standard',
          targets: [host.trim()],
          options: { port_range: portRange },
        }),
      });
      // poll for completion
      const poll = setInterval(async () => {
        const s = await api<any>(`/projects/${projectId}/scans/${res.scan.id}`);
        if (s.scan.status === 'completed' || s.scan.status === 'failed') {
          clearInterval(poll);
          setScanning(false);
          setScanResult(s.scan);
        }
      }, 3000);
    } catch (e: any) {
      setScanning(false);
      setScanError(e.message);
    }
  };

  const runPcap = async (file: File) => {
    if (!projectId) return;
    setPcapLoading(true);
    setPcapError('');
    setPcapResult(null);
    try {
      const res = await apiUpload<any>(`/projects/${projectId}/scans/uploads`, file, { kind: 'pcap' });
      setPcapResult(res);
    } catch (e: any) {
      setPcapError(e.message);
    } finally {
      setPcapLoading(false);
    }
  };

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>{t('network')}</h1>
      <p className="text-muted text-small mb-4">{t('networkDesc')}</p>

      <div className="tabs">
        <button className={tab === 'scan' ? 'tab active' : 'tab'} onClick={() => setTab('scan')}>⬡ {t('portScan')}</button>
        <button className={tab === 'diag' ? 'tab active' : 'tab'} onClick={() => setTab('diag')}>◎ {t('networkDiag')}</button>
        <button className={tab === 'pcap' ? 'tab active' : 'tab'} onClick={() => setTab('pcap')}>▤ {t('pcapAnalysis')}</button>
      </div>

      {tab === 'scan' && (
        <div className="grid-2" style={{ gridTemplateColumns: '1fr 1.5fr' }}>
          <Card title={t('portScan')}>
            <div className="form-group">
              <label className="form-label">{t('targetHost')}</label>
              <input className="form-input text-mono" value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.1" dir="ltr" />
            </div>
            <div className="form-group">
              <label className="form-label">{t('portRange')}</label>
              <select className="form-select" value={portRange} onChange={(e) => setPortRange(e.target.value)}>
                <option value="common">{t('common')}</option>
                <option value="top100">{t('top100')}</option>
                <option value="top1000">{t('top1000')}</option>
                <option value="full">{t('fullRange')}</option>
              </select>
            </div>
            <button className="btn btn-primary btn-block" onClick={runPortScan} disabled={scanning || !host.trim()}>
              {scanning ? t('scanningHost') : t('scanButton')}
            </button>
            {scanError && <FieldError message={scanError} />}
          </Card>

          <Card title={t('portScanResults')}>
            {scanning && <Spinner label={t('scanningHost')} />}
            {!scanning && !scanResult && <EmptyState icon="⬡" title={t('noData')} desc={t('networkDesc')} />}
            {scanResult && (
              <div>
                <div className="flex gap-4 mb-4 text-small">
                  <span><strong>{scanResult.services?.length || 0}</strong> {t('openPorts')}</span>
                  <span><strong>{scanResult.stats?.open || 0}</strong> open</span>
                  <span><strong>{scanResult.stats?.closed || 0}</strong> closed</span>
                </div>
                {(scanResult.services || []).map((s: any, i: number) => (
                  <div key={i} className="target-row">
                    <span className="target-status done" />
                    <div style={{ flex: 1 }}>
                      <div className="text-small font-bold">{s.name || 'unknown'} <span className="text-muted">:{s.port}/{s.protocol}</span></div>
                      <div className="text-small text-muted">{s.product} {s.version} {s.banner ? `· ${s.banner.slice(0, 60)}` : ''}</div>
                    </div>
                    {s.tls && <Badge kind="info">TLS</Badge>}
                  </div>
                ))}
                {(scanResult.config_issues || []).map((c: any, i: number) => (
                  <div key={`c${i}`} className="text-small" style={{ color: 'var(--yellow)' }}>⚠ {c}</div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === 'diag' && <DiagPanel host={host} setHost={setHost} />}

      {tab === 'pcap' && (
        <div className="grid-2" style={{ gridTemplateColumns: '1fr 1.5fr' }}>
          <Card title={t('pcapUpload')}>
            <p className="text-small text-muted mb-3">{t('pcapDesc')}</p>
            <p className="text-small text-muted mb-3">{t('pcapSupported')}</p>
            <input type="file" accept=".pcap,.pcapng" onChange={(e) => { const f = e.target.files?.[0]; if (f) runPcap(f); }} className="form-input" />
            {pcapLoading && <div className="mt-3"><Spinner /></div>}
            {pcapError && <FieldError message={pcapError} />}
          </Card>
          <Card title={t('pcapResults')}>
            {!pcapResult && !pcapLoading && <EmptyState icon="▤" title={t('noPcap')} />}
            {pcapResult && (
              <div className="text-small flex flex-col gap-2">
                <div><span className="text-muted">{t('packetsTotal')}: </span><strong>{pcapResult.stats?.total_packets || 0}</strong></div>
                <div><span className="text-muted">{t('protocols')}: </span>{(pcapResult.protocols || []).map((p: any) => `${p.name}(${p.count})`).join(', ') || '—'}</div>
                <div><span className="text-muted">{t('topTalkers')}: </span></div>
                <div style={{ paddingInlineStart: 16 }}>
                  {(pcapResult.top_talkers || []).slice(0, 8).map((tp: any, i: number) => (
                    <div key={i} className="text-muted">{tp.ip} — {tp.packets} pkts</div>
                  ))}
                </div>
                {(pcapResult.dns_queries || []).length > 0 && (
                  <>
                    <div className="mt-2"><span className="text-muted">{t('dnsQueries')}: </span></div>
                    <div style={{ paddingInlineStart: 16 }}>
                      {(pcapResult.dns_queries || []).slice(0, 10).map((q: any, i: number) => <div key={i} className="text-muted text-mono">{q}</div>)}
                    </div>
                  </>
                )}
                {(pcapResult.iocs || []).length > 0 && (
                  <>
                    <div className="mt-2"><span className="text-muted">{t('iocExtracted')}: </span></div>
                    {(pcapResult.iocs || []).slice(0, 10).map((ioc: any, i: number) => (
                      <div key={i} className="flex gap-2 items-center">
                        <Badge kind="medium">{ioc.type}</Badge>
                        <span className="text-mono">{ioc.value}</span>
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

function DiagPanel({ host, setHost }: { host: string; setHost: (v: string) => void }) {
  const { t } = useTranslation();
  const { projectId } = useUi();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const run = async (kind: string) => {
    if (!host.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await api<any>(`/projects/${projectId}/scans`, {
        method: 'POST',
        body: JSON.stringify({ name: `diag ${kind} ${host}`, kind: 'network', profile: 'quick', targets: [host.trim()], options: { diag: kind } }),
      });
      const poll = setInterval(async () => {
        const s = await api<any>(`/projects/${projectId}/scans/${res.scan.id}`);
        if (s.scan.status === 'completed' || s.scan.status === 'failed') {
          clearInterval(poll);
          setLoading(false);
          setResult(s.scan);
        }
      }, 3000);
    } catch (e: any) {
      setLoading(false);
      setError(e.message);
    }
  };

  return (
    <Card title={t('networkDiag')}>
      <div className="flex gap-3 mb-4">
        <input className="form-input text-mono" style={{ maxWidth: 280 }} value={host} onChange={(e) => setHost(e.target.value)} placeholder="host or IP" dir="ltr" />
        <button className="btn btn-secondary" onClick={() => run('dns')} disabled={loading || !host.trim()}>DNS</button>
        <button className="btn btn-secondary" onClick={() => run('tcp')} disabled={loading || !host.trim()}>TCP</button>
        <button className="btn btn-secondary" onClick={() => run('trace')} disabled={loading || !host.trim()}>Traceroute</button>
      </div>
      {loading && <Spinner />}
      {error && <FieldError message={error} />}
      {result && (
        <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 14, borderRadius: 8, overflow: 'auto', maxHeight: 300 }}>
          {JSON.stringify(result.stats || result, null, 2)}
        </pre>
      )}
    </Card>
  );
}
