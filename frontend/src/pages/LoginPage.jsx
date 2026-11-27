import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ShieldAlert, LogIn, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { extractErrorMessage } from '../api/client';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const registeredMessage = location.state?.registered
    ? 'Account created! Sign in with your credentials.'
    : '';
  const redirectTarget = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!identifier.trim() || !password) {
      setError('Please enter both your username/email and password.');
      return;
    }

    setSubmitting(true);
    try {
      await login(identifier.trim(), password);
      navigate(redirectTarget, { replace: true });
    } catch (err) {
      setError(extractErrorMessage(err, 'Invalid credentials. Please try again.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className="brand-icon">
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="brand-title" style={{ fontSize: '1.2rem' }}>
              RansomWatch
            </div>
            <div className="brand-sub">File-Activity Early Warning System</div>
          </div>
        </div>

        <div>
          <h1 style={{ margin: 0, fontSize: '1.25rem' }}>Sign in to console</h1>
          <p style={{ margin: '4px 0 0', fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
            Authenticate with your operator or administrator account.
          </p>
        </div>

        {registeredMessage && (
          <div className="alert alert-success">{registeredMessage}</div>
        )}

        {error && (
          <div className="alert alert-error">
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="form-group">
            <label className="form-label" htmlFor="login-identifier">
              Username or Email
            </label>
            <input
              id="login-identifier"
              type="text"
              className="input"
              placeholder="alice or alice@example.com"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="login-password">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              className="input"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={submitting}
            style={{ width: '100%', marginTop: 4 }}
          >
            <LogIn size={17} />
            {submitting ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', textAlign: 'center' }}>
          Need an operator account? <Link to="/register">Register here</Link>
        </div>
      </div>
    </div>
  );
}
