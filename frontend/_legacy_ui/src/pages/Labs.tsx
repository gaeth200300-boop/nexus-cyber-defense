import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, EmptyState } from '../components/ui';
import { fmtDate } from '../lib/utils';

export default function Labs() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [labs, setLabs] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [leaderboard, setLeaderboard] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [cat, setCat] = useState('');
  const [lvl, setLvl] = useState('');

  const load = () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (cat) params.set('category', cat);
    if (lvl) params.set('level', lvl);
    Promise.all([
      api<{ items: any[] }>(`/labs?${params}`),
      api<any>('/labs/me/stats'),
      api<{ items: any[] }>('/labs/leaderboard?limit=10'),
    ]).then(([l, s, lb]) => {
      setLabs(l.items); setStats(s); setLeaderboard(lb.items);
    }).catch((e) => setError(e.message)).finally(() => setLoading(false));
  };

  useEffect(load, [cat, lvl]);

  const categories = [...new Set(labs.map((l) => l.category))];
  const levels = [...new Set(labs.map((l) => l.level))];

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>{t('labs')}</h1>
      <p className="text-muted text-small mb-4">{t('challenges')}</p>

      {stats && (
        <div className="stat-grid mb-4">
          <StatCard icon="★" tone="low" value={stats.total_points || 0} label={t('totalPoints')} />
          <StatCard icon="⚗" tone="medium" value={`${stats.labs_completed || 0}/${stats.total_labs || labs.length}`} label={t('completedLabs')} />
          <StatCard icon="🏆" tone="high" value={stats.achievements?.length || 0} label={t('achievementsEarned')} />
        </div>
      )}

      <div className="flex gap-3 mb-4">
        <select className="form-select" style={{ maxWidth: 180 }} value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="">{t('all')} {t('category')}</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="form-select" style={{ maxWidth: 180 }} value={lvl} onChange={(e) => setLvl(e.target.value)}>
          <option value="">{t('all')} {t('levels')}</option>
          {levels.map((l) => <option key={l} value={l}>{t(l)}</option>)}
        </select>
      </div>

      {loading ? <Spinner /> : error ? <p style={{ color: 'var(--red)' }}>{error}</p> : labs.length === 0 ? (
        <Card><EmptyState icon="⚗" title={t('noData')} /></Card>
      ) : (
        <div className="grid-3">
          {labs.map((l) => (
            <Card key={l.id} hover className="card-hover">
              <div className="flex items-center justify-between mb-2">
                <Badge kind={l.level}>{t(l.level)}</Badge>
                {l.user_state?.completed && <Badge kind="completed">✓</Badge>}
              </div>
              <div className="font-bold mb-1" style={{ fontSize: 14 }}>{l.title_ar || l.title_en}</div>
              <p className="text-muted text-small mb-3" style={{ minHeight: 36 }}>{l.description_ar || l.description_en}</p>
              <div className="flex gap-3 text-small text-muted mb-3">
                <span>◈ {l.category}</span>
                <span>★ {l.points} {t('points')}</span>
                {l.requires_private_access && <span>🔒 {t('isolated')}</span>}
              </div>
              <button className="btn btn-primary btn-block btn-sm" onClick={() => nav(`/labs/${l.id}`)}>
                {l.user_state?.active ? t('continueLab') : t('startLab')}
              </button>
            </Card>
          ))}
        </div>
      )}

      {leaderboard.length > 0 && (
        <Card title={t('leaderboard')} className="mt-4">
          {leaderboard.map((p, i) => (
            <div key={p.user_id || i} className="target-row">
              <span className="font-bold" style={{ width: 28, color: i < 3 ? 'var(--yellow)' : 'var(--txt-2)' }}>#{i + 1}</span>
              <span style={{ flex: 1 }}>{p.full_name || p.email}</span>
              <Badge kind="info">{p.total_points} pts</Badge>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

function StatCard({ icon, tone, value, label }: { icon: string; tone: string; value: any; label: string }) {
  const tones: Record<string, string> = { neutral: 'var(--violet-soft);color:var(--violet)', low: 'var(--green-soft);color:var(--green)', medium: 'var(--yellow-soft);color:var(--yellow)', high: 'var(--red-soft);color:var(--red)', info: 'var(--cyan-soft);color:var(--cyan)' };
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ background: tones[tone]?.split(';')[0], color: tones[tone]?.split(';')[1] }}>{icon}</div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
