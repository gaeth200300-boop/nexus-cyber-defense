import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner } from '../components/ui';

export default function SearchResults() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const nav = useNavigate();
  const q = params.get('q') || '';
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!q) return;
    setLoading(true);
    api<any>(`/system/search?q=${encodeURIComponent(q)}&limit=20`)
      .then(setResults)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [q]);

  if (loading) return <Spinner />;
  if (!results) return null;

  const groups = results.groups || [];

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>{t('search')}: "{q}"</h1>
      <p className="text-muted text-small mb-4">{results.total || 0} {t('results')}</p>

      {groups.map((g: any) => (
        <Card key={g.type} title={g.type} className="mb-3">
          {g.items.map((item: any) => (
            <div key={item.id} className="target-row cursor-pointer" onClick={() => {
              if (g.type === 'findings') nav(`/findings/${item.id}`);
              else if (g.type === 'assets') nav(`/assets?id=${item.id}`);
              else if (g.type === 'scans') nav(`/scans/${item.id}`);
            }}>
              <div style={{ flex: 1 }}>
                <div className="text-small font-bold">{item.title || item.name || item.value}</div>
                <div className="text-small text-muted">{item.description || item.email || ''}</div>
              </div>
              {item.severity && <Badge kind={item.severity}>{item.severity}</Badge>}
              {item.status && <Badge kind={item.status}>{item.status}</Badge>}
            </div>
          ))}
        </Card>
      ))}

      {groups.length === 0 && <Card><div className="text-muted text-center py-8">{t('noResults')}</div></Card>}
    </div>
  );
}
