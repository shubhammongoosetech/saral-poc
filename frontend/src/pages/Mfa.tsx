import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { mfaApi, walletApi } from '../api/endpoints';
import { useAuth } from '../hooks/useAuth';
import { getCurrentCoords } from '../hooks/useLocation';

export const Mfa: React.FC = () => {
  const navigate = useNavigate();
  const { updateToken, isAuthenticated } = useAuth();

  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [countdown, setCountdown] = useState(30);
  const [error, setError] = useState<string | null>(null);

  const sendCode = useCallback(async () => {
    try {
      const res = await mfaApi.sendMfaOtp();
      if (res.devOtp) {
        setCode(res.devOtp);
      }
      setCountdown(30);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to send verification code');
    }
  }, []);

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
      return;
    }
    sendCode();
  }, [isAuthenticated, navigate, sendCode]);

  useEffect(() => {
    if (countdown <= 0) return;
    const timer = setInterval(() => {
      setCountdown((c) => Math.max(0, c - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [countdown]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code || code.trim().length !== 6) {
      setError('Please enter the 6-digit code');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await mfaApi.verifyMfaOtp(code.trim());
      updateToken(res.token);

      if (!res.hasPolicy) {
        navigate('/working-policy');
        return;
      }

      const coords = await getCurrentCoords();
      const check = await walletApi.checkAccess(coords.lat, coords.lng);
      if (check.allowed) {
        navigate('/wallet');
      } else {
        setError(
          check.reason
            ? `Access blocked: ${check.reason}`
            : 'Access allowed only during your working time and location.'
        );
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Enter code</h1>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleVerify}>
        <div className="field">
          <input
            id="mfaCode"
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
          {loading ? 'Verifying...' : 'Verify'}
        </button>

        <div className="field text-center">
          {countdown > 0 ? (
            <span className="muted helper-text">Resend code in {countdown}s</span>
          ) : (
            <button
              type="button"
              className="btn-link helper-text"
              onClick={sendCode}
              disabled={loading}
            >
              Resend code
            </button>
          )}
        </div>
      </form>
    </div>
  );
};

export default Mfa;
