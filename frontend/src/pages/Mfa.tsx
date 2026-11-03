import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { mfaApi } from '../api/endpoints';
import { useAuth } from '../hooks/useAuth';

export const Mfa: React.FC = () => {
  const navigate = useNavigate();
  const { updateToken, isAuthenticated } = useAuth();

  const [otp, setOtp] = useState('');
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [codeSent, setCodeSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  // Auto-send MFA OTP code on initial mount
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
      return;
    }

    const sendInitialCode = async () => {
      try {
        setSending(true);
        const res = await mfaApi.sendMfaOtp();
        setCodeSent(true);
        setMessage(res.message);
        if (res.devOtp) {
          setDevOtp(res.devOtp);
        }
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to dispatch MFA verification code');
      } finally {
        setSending(false);
      }
    };

    sendInitialCode();
  }, [isAuthenticated, navigate]);

  const handleResend = async () => {
    try {
      setSending(true);
      setError(null);
      const res = await mfaApi.sendMfaOtp();
      setMessage(res.message);
      if (res.devOtp) {
        setDevOtp(res.devOtp);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to resend code');
    } finally {
      setSending(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setError('Please enter the 6-digit verification code');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await mfaApi.verifyMfaOtp(otp.trim());
      updateToken(res.token);

      if (!res.hasPolicy) {
        navigate('/working-policy');
      } else {
        navigate('/review');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Two-Factor Authentication</h1>
      <p className="page-subtitle">Verify your identity with the second factor security code</p>

      {error && <div className="alert alert-danger">{error}</div>}
      {message && <div className="alert alert-success">{message}</div>}

      <form onSubmit={handleVerify}>
        {devOtp && (
          <div className="policy-block" style={{ marginBottom: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px' }}>
              Dev MFA Code: <strong className="text-mono" style={{ fontSize: '14px', letterSpacing: '1px' }}>{devOtp}</strong>
            </span>
            <button
              type="button"
              className="copy-btn"
              onClick={() => setOtp(devOtp)}
            >
              Auto-fill
            </button>
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="mfaInput">
            Verification Code (6 Digits)
          </label>
          <input
            id="mfaInput"
            type="text"
            maxLength={6}
            className="form-input text-mono"
            placeholder="123456"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            disabled={loading}
            autoFocus
          />
        </div>

        <button
          type="submit"
          className="btn btn-primary"
          disabled={loading || otp.length !== 6}
          style={{ marginBottom: '12px' }}
        >
          {loading ? 'Verifying...' : 'Verify MFA'}
        </button>

        <button
          type="button"
          className="btn btn-outline"
          onClick={handleResend}
          disabled={sending || loading}
        >
          {sending ? 'Sending code...' : 'Resend Code'}
        </button>
      </form>
    </div>
  );
};
