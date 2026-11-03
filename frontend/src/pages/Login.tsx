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
  const [otp, setOtp] = useState('');
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [otpSent, setOtpSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const googleBtnRef = useRef<HTMLDivElement>(null);

  // If already authenticated and MFA verified, redirect forward
  useEffect(() => {
    // Keep user on login if they just landed or logged out
  }, [isAuthenticated]);

  // Initialize Google Sign-In button
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
          width: 380,
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

  const handleRequestOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mobile || mobile.trim().length < 8) {
      setError('Please enter a valid mobile number with country code (e.g. +919876543210)');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await authApi.requestOtp(mobile.trim());
      setOtpSent(true);
      setSuccessMessage(res.message);
      if (res.devOtp) {
        setDevOtp(res.devOtp);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to dispatch OTP code');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setError('Please enter the 6-digit OTP code');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await authApi.verifyOtp(mobile.trim(), otp.trim());
      setSession(res.token, res.user);
      navigate('/mfa');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Invalid OTP code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Sign In with SARAL</h1>
      <p className="page-subtitle">Access your non-custodial decentralized key container</p>

      {error && <div className="alert alert-danger">{error}</div>}
      {successMessage && <div className="alert alert-success">{successMessage}</div>}

      {/* Google OAuth Option */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '20px' }}>
        <div ref={googleBtnRef} style={{ minHeight: '44px' }}></div>
      </div>

      <div className="divider">or continue with mobile</div>

      {/* Mobile Number + OTP Option */}
      {!otpSent ? (
        <form onSubmit={handleRequestOtp}>
          <div className="form-group">
            <label className="form-label" htmlFor="mobileInput">
              Mobile Number
            </label>
            <input
              id="mobileInput"
              type="tel"
              className="form-input"
              placeholder="+91 98765 43210"
              value={mobile}
              onChange={(e) => setMobile(e.target.value)}
              disabled={loading}
              autoFocus
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading || !mobile}>
            {loading ? 'Sending OTP...' : 'Send OTP'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerifyOtp}>
          {devOtp && (
            <div className="policy-block" style={{ marginBottom: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px' }}>
                Dev OTP: <strong className="text-mono" style={{ fontSize: '14px', letterSpacing: '1px' }}>{devOtp}</strong>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label className="form-label" htmlFor="otpInput" style={{ margin: 0 }}>
                Enter 6-digit OTP
              </label>
              <button
                type="button"
                className="copy-btn"
                onClick={() => setOtpSent(false)}
                style={{ fontSize: '11px', padding: '2px 6px' }}
              >
                Change number
              </button>
            </div>
            <input
              id="otpInput"
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

          <button type="submit" className="btn btn-primary" disabled={loading || otp.length !== 6}>
            {loading ? 'Verifying...' : 'Verify & Continue'}
          </button>
        </form>
      )}
    </div>
  );
};
