import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { authApi } from '../api/endpoints';
import { useAuth } from '../hooks/useAuth';

declare global {
  interface Window {
    google?: any;
  }
}

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { setSession, isAuthenticated } = useAuth();

  const [mobile, setMobile] = useState('');
  const [code, setCode] = useState('');
  const [codeSent, setCodeSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const googleBtnRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/wallet');
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    const clientId =
      import.meta.env.VITE_GOOGLE_CLIENT_ID ||
      'your-google-client-id.apps.googleusercontent.com';

    const handleGoogleCredential = async (response: any) => {
      try {
        setLoading(true);
        setError(null);
        const res = await authApi.loginWithGoogle(response.credential);
        setSession(res.token, res.user);
        navigate('/mfa');
      } catch (err: any) {
        setError(err.response?.data?.error || 'Google authentication failed');
      } finally {
        setLoading(false);
      }
    };

    const initGoogle = () => {
      if (window.google?.accounts?.id && googleBtnRef.current) {
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: handleGoogleCredential,
        });
        window.google.accounts.id.renderButton(googleBtnRef.current, {
          theme: 'outline',
          size: 'large',
          width: 320,
          text: 'continue_with',
        });
      }
    };

    if (window.google?.accounts?.id) {
      initGoogle();
    } else {
      const interval = setInterval(() => {
        if (window.google?.accounts?.id) {
          clearInterval(interval);
          initGoogle();
        }
      }, 200);
      return () => clearInterval(interval);
    }
  }, [navigate, setSession]);

  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mobile || mobile.trim().length < 8) {
      setError('Please enter a valid mobile number');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const res = await authApi.requestOtp(mobile.trim());
      setCodeSent(true);
      if (res.devOtp) {
        setCode(res.devOtp);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to send code');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code || code.trim().length !== 6) {
      setError('Please enter the 6-digit code');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const res = await authApi.verifyOtp(mobile.trim(), code.trim());
      setSession(res.token, res.user);
      navigate('/mfa');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Invalid code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Sign in</h1>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="field">
        <div ref={googleBtnRef}></div>
      </div>

      <div className="divider">or</div>

      {!codeSent ? (
        <form onSubmit={handleSendCode}>
          <div className="field">
            <label className="label" htmlFor="mobileInput">
              Mobile number
            </label>
            <input
              id="mobileInput"
              type="tel"
              className="input"
              placeholder="+91 98765 43210"
              value={mobile}
              onChange={(e) => setMobile(e.target.value)}
              disabled={loading}
              autoFocus
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || !mobile.trim()}
          >
            {loading ? 'Sending code...' : 'Send code'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerifyCode}>
          <div className="field">
            <div className="inline-row">
              <label className="label" htmlFor="codeInput">
                Enter code
              </label>
              <button
                type="button"
                className="btn-link helper-text"
                onClick={() => setCodeSent(false)}
              >
                Change number
              </button>
            </div>
            <input
              id="codeInput"
              type="text"
              maxLength={6}
              className="input text-mono"
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              disabled={loading}
              autoFocus
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || code.trim().length !== 6}
          >
            {loading ? 'Verifying...' : 'Sign in'}
          </button>
        </form>
      )}
    </div>
  );
};

export default Login;
