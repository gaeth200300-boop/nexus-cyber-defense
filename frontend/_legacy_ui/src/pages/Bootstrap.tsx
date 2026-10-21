import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, setTokens, ApiError } from '../lib/api';
import { useAuth } from '../lib/store';
import { FieldError } from '../components/ui';

export default function BootstrapPage() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const setUser = useAuth((s) => s.setUser);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Bootstrap is only valid while the platform has no accounts. If an account
  // already exists (for example after a previous setup), send the visitor to
  // the sign-in page instead of showing a form that can only fail with 409.
  useEffect(() => {
    let active = true;
    api<{ bootstrap_required: boolean }>('/auth/bootstrap')
      .then((d) => {
        if (active && !d.bootstrap_required) nav('/login', { replace: true });
      })
      .catch(() => { /* keep the form visible if the API is unreachable */ });
    return () => { active = false; };
  }, [nav]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password.length < 12) { setError(t('passwordTooShort')); return; }
    setError('');
    setLoading(true);
    try {
      const res = await api<any>('/auth/bootstrap', {
        method: 'POST',
        body: JSON.stringify({ email, full_name: fullName, password }),
      });
      setTokens(res.access_token, res.refresh_token);
      setUser(res.user);
      nav('/dashboard');
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          nav('/login', { replace: true });
          return;
        }
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <div className="auth-logo-mark">N</div>
          <div style={{ fontSize: 22, fontWeight: 800 }}>{t('appName')}</div>
          <div style={{ fontSize: 11, color: 'var(--violet)', letterSpacing: 3, fontWeight: 700 }}>{t('appSuffix')}</div>
        </div>
        <div className="card">
          <h2 style={{ marginBottom: 4 }}>{t('bootstrap')}</h2>
          <p className="text-muted text-small mb-4">{t('bootstrapDesc')}</p>
          <form onSubmit={submit}>
            <div className="form-group">
              <label className="form-label">{t('fullName')}</label>
              <input className="form-input" value={fullName} onChange={(e) => setFullName(e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">{t('email')}</label>
              <input className="form-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required dir="ltr" />
            </div>
            <div className="form-group">
              <label className="form-label">{t('password')}</label>
              <input className="form-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required dir="ltr" minLength={12} />
              <div className="form-hint">{t('passwordTooShort')}</div>
            </div>
            {error && <FieldError message={error} />}
            <button className="btn btn-primary btn-block" disabled={loading}>
              {loading ? t('loading') : t('createAccount')}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
