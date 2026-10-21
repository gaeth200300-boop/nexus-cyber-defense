import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, setTokens, ApiError } from '../lib/api';
import { useAuth } from '../lib/store';
import { FieldError } from '../components/ui';

type AuthMode = 'login' | 'register';

export default function LoginPage() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const setUser = useAuth((s) => s.setUser);
  const [mode, setMode] = useState<AuthMode>('login');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [mfaNeeded, setMfaNeeded] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let active = true;
    api<{ bootstrap_required: boolean }>('/auth/bootstrap')
      .then((d) => {
        if (active && d.bootstrap_required) nav('/bootstrap', { replace: true });
      })
      .catch(() => { /* keep the sign-in form if the API is unreachable */ });
    return () => { active = false; };
  }, [nav]);

  const switchMode = (next: AuthMode) => {
    setMode(next);
    setError('');
    setSuccess('');
    setMfaNeeded(false);
    setTotp('');
    setPassword('');
    setConfirmPassword('');
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (mode === 'register') {
      if (password.length < 12) {
        setError(t('passwordTooShort'));
        return;
      }
      if (password !== confirmPassword) {
        setError(t('passwordMismatch'));
        return;
      }
      setLoading(true);
      try {
        await api('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ email, full_name: fullName, password }),
        });
        setMode('login');
        setPassword('');
        setConfirmPassword('');
        setMfaNeeded(false);
        setTotp('');
        setSuccess(t('accountCreated'));
      } catch (err) {
        if (err instanceof ApiError) {
          if (err.code === 'email_taken') setError(t('userExists'));
          else if (err.code === 'weak_password') setError(t('weakPassword'));
          else if (err.code === 'bootstrap_required') setError(t('bootstrapRequired'));
          else if (err.code === 'invalid_email') setError(t('invalidEmail'));
          else if (err.code === 'validation_error') setError(t('invalidInput'));
          else if (err.code === 'rate_limited') setError(t('rateLimited'));
          else setError(err.message);
        } else {
          setError(t('networkError'));
        }
      } finally {
        setLoading(false);
      }
      return;
    }

    setLoading(true);
    try {
      const res = await api<any>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password, totp_code: totp || undefined }),
      });
      setTokens(res.access_token, res.refresh_token);
      setUser(res.user);
      nav('/dashboard');
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401 && err.code === 'mfa_required') {
          setMfaNeeded(true);
        } else {
          setError(err.message);
        }
      } else {
        setError(t('networkError'));
      }
    } finally {
      setLoading(false);
    }
  };

  const isRegister = mode === 'register';

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <div className="auth-logo-mark">N</div>
          <div style={{ fontSize: 22, fontWeight: 800 }}>{t('appName')}</div>
          <div style={{ fontSize: 11, color: 'var(--violet)', letterSpacing: 3, fontWeight: 700 }}>{t('appSuffix')}</div>
        </div>
        <div className="card">
          <h2 style={{ marginBottom: 4 }}>{isRegister ? t('registerTitle') : t('welcomeBack')}</h2>
          <p className="text-muted text-small mb-4">{isRegister ? t('registerSubtitle') : t('loginSubtitle')}</p>
          <form onSubmit={submit}>
            {isRegister && (
              <div className="form-group">
                <label className="form-label">{t('fullName')}</label>
                <input
                  className="form-input"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required
                  dir="auto"
                  autoComplete="name"
                />
              </div>
            )}
            <div className="form-group">
              <label className="form-label">{t('email')}</label>
              <input
                className="form-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                dir="ltr"
                autoComplete="email"
              />
            </div>
            <div className="form-group">
              <label className="form-label">{t('password')}</label>
              <input
                className="form-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                dir="ltr"
                minLength={isRegister ? 12 : undefined}
                autoComplete={isRegister ? 'new-password' : 'current-password'}
              />
              {isRegister && <div className="form-hint">{t('passwordHint')}</div>}
            </div>
            {isRegister && (
              <div className="form-group">
                <label className="form-label">{t('confirmPassword')}</label>
                <input
                  className="form-input"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  dir="ltr"
                  minLength={12}
                  autoComplete="new-password"
                />
              </div>
            )}
            {!isRegister && mfaNeeded && (
              <div className="form-group">
                <label className="form-label">{t('totpCode')}</label>
                <input
                  className="form-input"
                  value={totp}
                  onChange={(e) => setTotp(e.target.value)}
                  placeholder="000000"
                  dir="ltr"
                  maxLength={10}
                />
              </div>
            )}
            {success && <div className="auth-success">{success}</div>}
            {error && <FieldError message={error} />}
            <button className="btn btn-primary btn-block" disabled={loading}>
              {loading ? t('loading') : isRegister ? t('createAccount') : mfaNeeded ? t('verify') : t('signIn')}
            </button>
          </form>
          {!mfaNeeded && (
            <div className="auth-switch">
              {isRegister ? (
                <button type="button" onClick={() => switchMode('login')}>{t('alreadyHaveAccount')}</button>
              ) : (
                <>
                  {t('noAccount')}{' '}
                  <button type="button" onClick={() => switchMode('register')}>{t('createAccount')}</button>
                </>
              )}
            </div>
          )}
        </div>
        <p className="text-center text-small text-muted mt-4">
          NEXUS Cyber Defense — {t('authorizedOnly')}
        </p>
      </div>
    </div>
  );
}
