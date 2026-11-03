import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { mfaApi, walletApi, PolicyCheckResponse } from '../api/endpoints';
import { useAuth } from '../hooks/useAuth';
import { AccessDeniedModal } from '../components/AccessDeniedModal';

/**
 * Helper to fetch current coordinates with fallback to Indore defaults
 */
function getCurrentCoordinates(): Promise<{ lat: number; lng: number }> {
  return new Promise((resolve) => {
    if (!navigator.geolocation) {
      resolve({ lat: 22.7196, lng: 75.8577 });
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      () => resolve({ lat: 22.7196, lng: 75.8577 }),
      { timeout: 6000, enableHighAccuracy: true, maximumAge: 30000 }
    );
  });
}

export const Mfa: React.FC = () => {
  const navigate = useNavigate();
  const { updateToken, isAuthenticated, logout } = useAuth();

  const [otp, setOtp] = useState('');
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifyingPolicy, setVerifyingPolicy] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  // Policy check modal state for second-time / returning users
  const [showDeniedModal, setShowDeniedModal] = useState(false);
  const [deniedInfo, setDeniedInfo] = useState<{
    reason: string;
    details?: PolicyCheckResponse['details'];
  }>({ reason: '' });
  const [retrying, setRetrying] = useState(false);

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

      // CASE 1: First time user (has no policy configured yet) -> allowed to set policy
      if (!res.hasPolicy) {
        navigate('/working-policy');
        return;
      }

      // CASE 2: Second time / returning user (has policy configured) -> check working hours & location
      setVerifyingPolicy(true);
      const coords = await getCurrentCoordinates();

      try {
        const policyCheck = await walletApi.checkAccess(coords.lat, coords.lng);
        if (policyCheck.allowed) {
          // Allowed: proceed to review
          navigate('/review');
        } else {
          // Access blocked by policy gate: display modal and disallow entering
          setDeniedInfo({
            reason: policyCheck.reason,
            details: policyCheck.details,
          });
          setShowDeniedModal(true);
        }
      } catch (policyErr: any) {
        setDeniedInfo({
          reason: policyErr.response?.data?.error || 'Access policy evaluation failed',
        });
        setShowDeniedModal(true);
      } finally {
        setVerifyingPolicy(false);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRetryPolicyCheck = async () => {
    try {
      setRetrying(true);
      const coords = await getCurrentCoordinates();
      const policyCheck = await walletApi.checkAccess(coords.lat, coords.lng);

      if (policyCheck.allowed) {
        setShowDeniedModal(false);
        navigate('/review');
      } else {
        setDeniedInfo({
          reason: policyCheck.reason,
          details: policyCheck.details,
        });
      }
    } catch (err: any) {
      setDeniedInfo({
        reason: err.response?.data?.error || 'Policy check failed on retry.',
      });
    } finally {
      setRetrying(false);
    }
  };

  return (
    <>
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
              disabled={loading || verifyingPolicy}
              autoFocus
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || verifyingPolicy || otp.length !== 6}
            style={{ marginBottom: '12px' }}
          >
            {verifyingPolicy
              ? 'Checking Working Policy & Location...'
              : loading
              ? 'Verifying...'
              : 'Verify MFA'}
          </button>

          <button
            type="button"
            className="btn btn-outline"
            onClick={handleResend}
            disabled={sending || loading || verifyingPolicy}
          >
            {sending ? 'Sending code...' : 'Resend Code'}
          </button>
        </form>
      </div>

      {/* Access Denied Modal for returning users outside working policy */}
      <AccessDeniedModal
        isOpen={showDeniedModal}
        reason={deniedInfo.reason}
        details={deniedInfo.details}
        onRetry={handleRetryPolicyCheck}
        onLogout={logout}
        retrying={retrying}
      />
    </>
  );
};
