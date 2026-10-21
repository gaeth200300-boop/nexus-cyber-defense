import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Pagination, Modal, FieldError } from '../components/ui';
import { fmtDate } from '../lib/utils';

export default function Users() {
  const { t } = useTranslation();
  const [users, setUsers] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [showNew, setShowNew] = useState(false);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState('analyst');
  const [password, setPassword] = useState('');
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState('');
  const [showKeys, setShowKeys] = useState(false);
  const [keys, setKeys] = useState<any[]>([]);
  const [showNewKey, setShowNewKey] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [keyScopes, setKeyScopes] = useState('read');
  const [newKey, setNewKey] = useState('');

  const load = () => {
    setLoading(true);
    api<{ items: any[]; total: number }>(`/users?limit=25&offset=${(page - 1) * 25}`)
      .then((d) => { setUsers(d.items); setTotal(d.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(load, [page]);

  const create = async () => {
    setCreating(true);
    setCreateErr('');
    try {
      await api('/users', { method: 'POST', body: JSON.stringify({ email, full_name: fullName, role, password }) });
      setShowNew(false);
      load();
    } catch (e: any) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  };

  const toggleActive = async (u: any) => {
    await api(`/users/${u.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: !u.is_active }) });
    load();
  };

  const loadKeys = () => {
    api<{ items: any[] }>('/apikeys').then((d) => setKeys(d.items)).catch(() => {});
  };

  useEffect(() => { if (showKeys) loadKeys(); }, [showKeys]);

  const createKey = async () => {
    const res = await api<any>('/apikeys', {
      method: 'POST',
      body: JSON.stringify({ name: keyName, scopes: keyScopes.split(',').map((s) => s.trim()) }),
    });
    setNewKey(res.key);
    setShowNewKey(false);
    loadKeys();
  };

  const revokeKey = async (id: string) => {
    await api(`/apikeys/${id}`, { method: 'DELETE' });
    loadKeys();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('userManagement')}</h1>
        <div className="flex gap-2">
          <button className="btn btn-secondary btn-sm" onClick={() => setShowKeys(true)}>🔑 {t('apiKeys')}</button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowNew(true)}>+ {t('createUser')}</button>
        </div>
      </div>

      {loading ? <Spinner /> : (
        <Card>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>{t('userEmail')}</th><th>{t('userFullName')}</th><th>{t('userRole')}</th><th>{t('userActive')}</th><th>{t('userLastLogin')}</th><th>{t('actions')}</th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="text-mono text-small">{u.email}</td>
                    <td>{u.full_name}</td>
                    <td><Badge kind={u.role}>{t(`role${u.role.charAt(0).toUpperCase() + u.role.slice(1)}`)}</Badge></td>
                    <td><Badge kind={u.is_active ? 'enabled' : 'disabled'}>{u.is_active ? t('active') : t('disabled')}</Badge></td>
                    <td className="text-small text-muted">{fmtDate(u.last_login_at)}</td>
                    <td><button className="btn btn-ghost btn-sm" onClick={() => toggleActive(u)}>{u.is_active ? t('deactivate') : t('activate')}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={25} total={total} onPage={setPage} />
        </Card>
      )}

      {showNew && (
        <Modal title={t('createUserTitle')} onClose={() => setShowNew(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={create} disabled={creating}>{creating ? t('loading') : t('createUser')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('userFullName')}</label>
            <input className="form-input" value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('userEmail')}</label>
            <input className="form-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} dir="ltr" />
          </div>
          <div className="form-group">
            <label className="form-label">{t('userRole')}</label>
            <select className="form-select" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="viewer">{t('roleViewer')}</option>
              <option value="analyst">{t('roleAnalyst')}</option>
              <option value="admin">{t('roleAdmin')}</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">{t('password')}</label>
            <input className="form-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} dir="ltr" minLength={12} />
          </div>
          {createErr && <FieldError message={createErr} />}
        </Modal>
      )}

      {showKeys && (
        <Modal title={t('apiKeysManagement')} size="lg" onClose={() => setShowKeys(false)} footer={<button className="btn btn-secondary" onClick={() => setShowKeys(false)}>{t('close')}</button>}>
          <button className="btn btn-primary btn-sm mb-3" onClick={() => setShowNewKey(true)}>+ {t('createKey')}</button>
          {keys.length === 0 && <div className="text-muted text-small">{t('noKeys')}</div>}
          {keys.map((k) => (
            <div key={k.id} className="target-row">
              <div style={{ flex: 1 }}>
                <div className="font-bold text-small">{k.name}</div>
                <div className="text-small text-muted">{k.prefix}… · {k.scopes?.join(', ')} · {t('revoked')}: {k.revoked ? t('yes') : t('no')}</div>
              </div>
              {!k.revoked && <button className="btn btn-danger btn-sm" onClick={() => revokeKey(k.id)}>{t('revoke')}</button>}
            </div>
          ))}
        </Modal>
      )}

      {showNewKey && (
        <Modal title={t('createKey')} onClose={() => setShowNewKey(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNewKey(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={createKey}>{t('createKey')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('keyName')}</label>
            <input className="form-input" value={keyName} onChange={(e) => setKeyName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('apiKeyScopes')}</label>
            <input className="form-input" value={keyScopes} onChange={(e) => setKeyScopes(e.target.value)} dir="ltr" />
            <div className="form-hint">read, write, admin</div>
          </div>
        </Modal>
      )}

      {newKey && (
        <Modal title={t('keyCreated')} onClose={() => setNewKey('')} footer={<button className="btn btn-primary" onClick={() => { navigator.clipboard.writeText(newKey); setNewKey(''); }}>{t('copyKey')}</button>}>
          <p className="text-small text-muted mb-2">{t('copyAndStore')}</p>
          <pre className="text-mono text-small" style={{ background: 'var(--bg-2)', padding: 12, borderRadius: 8, wordBreak: 'break-all' }}>{newKey}</pre>
        </Modal>
      )}
    </div>
  );
}
