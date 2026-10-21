import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, ApiError } from '../lib/api';
import { Card, Badge, Spinner } from '../components/ui';
import { useUi } from '../lib/store';

interface Msg { role: 'user' | 'assistant'; text: string; citations?: string[] }

export default function Copilot() {
  const { t } = useTranslation();
  const { projectId } = useUi();
  const [status, setStatus] = useState<any>(null);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);

  const loadStatus = () => {
    if (!projectId) return;
    api<any>(`/projects/${projectId}/copilot/status`).then(setStatus).catch(() => {});
  };

  useEffect(loadStatus, [projectId]);

  const send = async () => {
    if (!input.trim() || loading) return;
    const msg = input.trim();
    setInput('');
    setMessages((m) => [...m, { role: 'user', text: msg }]);
    setLoading(true);
    setError('');
    try {
      const res = await api<any>(`/projects/${projectId}/copilot/chat`, {
        method: 'POST',
        body: JSON.stringify({ message: msg, lang: 'ar', history: messages.slice(-10).map((m) => ({ role: m.role, content: m.text })) }),
      });
      setMessages((m) => [...m, { role: 'assistant', text: res.analysis || res.reply || JSON.stringify(res), citations: res.citations }]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const quickAsk = (q: string) => { setInput(q); };

  const available = status?.copilot?.available || false;

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('copilot')}</h1>
        <Badge kind={available ? 'enabled' : 'disabled'}>
          {available ? (status?.copilot?.provider || 'AI') : t('copilotUnavailable')}
        </Badge>
      </div>

      {!available && (
        <Card className="mb-4" style={{ borderColor: 'var(--yellow)' }}>
          <div className="flex items-center gap-3">
            <span style={{ fontSize: 20 }}>⚙</span>
            <div style={{ flex: 1 }}>
              <strong>{t('copilotUnavailable')}</strong>
              <div className="text-small text-muted">{t('configureProvider')}</div>
            </div>
          </div>
        </Card>
      )}

      <Card title={t('chat')} subtitle={t('askAboutFindings')}>
        <div style={{ minHeight: 320, maxHeight: 480, overflowY: 'auto', marginBottom: 16, padding: '0 4px' }}>
          {messages.length === 0 && (
            <div className="text-center mt-8 mb-8">
              <div style={{ fontSize: 36, marginBottom: 8 }}>✦</div>
              <div className="font-bold mb-2">{t('chatWelcome')}</div>
              <div className="flex flex-wrap gap-2 justify-center mt-3">
                <button className="btn btn-secondary btn-sm" onClick={() => quickAsk(t('suggestExplain'))}>💡 {t('suggestExplain')}</button>
                <button className="btn btn-secondary btn-sm" onClick={() => quickAsk(t('suggestPrioritize'))}>⚡ {t('suggestPrioritize')}</button>
                <button className="btn btn-secondary btn-sm" onClick={() => quickAsk(t('suggestSummarize'))}>▤ {t('suggestSummarize')}</button>
                <button className="btn btn-secondary btn-sm" onClick={() => quickAsk(t('suggestRemediation'))}>🔧 {t('suggestRemediation')}</button>
              </div>
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'} mb-3`}>
              <div style={{
                maxWidth: '75%',
                padding: '10px 14px',
                borderRadius: 12,
                background: m.role === 'user' ? 'var(--violet-soft)' : 'var(--bg-2)',
                border: `1px solid ${m.role === 'user' ? 'rgba(124,92,255,0.3)' : 'var(--line-soft)'}`,
                fontSize: 13,
                lineHeight: 1.6,
              }}>
                {m.text}
                {m.citations && m.citations.length > 0 && (
                  <div className="mt-2 pt-2" style={{ borderTop: '1px solid var(--line-soft)' }}>
                    <div className="text-small text-muted mb-1">{t('citations_note')}</div>
                    {m.citations.slice(0, 3).map((c, j) => (
                      <div key={j} className="text-small">📎 {c}</div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start mb-3">
              <div style={{ padding: '10px 14px', borderRadius: 12, background: 'var(--bg-2)', border: '1px solid var(--line-soft)' }}>
                <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {error && <p style={{ color: 'var(--red)', fontSize: 12, marginBottom: 8 }}>{error}</p>}

        <div className="flex gap-2">
          <input
            className="form-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
            placeholder={t('askCopilot')}
            disabled={!available}
          />
          <button className="btn btn-primary" onClick={send} disabled={loading || !available}>
            {loading ? t('thinking') : t('send')}
          </button>
        </div>
      </Card>

      {status?.budget && (
        <Card title={t('budget')} className="mt-4">
          <div className="flex gap-4 text-small">
            <span>{t('tokensUsed')}: <strong>{status.budget.used_tokens || 0}</strong></span>
            <span>{t('budget')}: <strong>{status.budget.monthly_budget || '—'}</strong></span>
          </div>
          <div className="progress mt-2">
            <div className="progress-bar" style={{ width: `${Math.min(100, ((status.budget.used_tokens || 0) / (status.budget.monthly_budget || 1)) * 100)}%` }} />
          </div>
        </Card>
      )}
    </div>
  );
}
