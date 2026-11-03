import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi, walletApi, PolicyCheckResponse } from '../api/endpoints';
import { useAuth } from '../hooks/useAuth';
import { AccessDeniedModal } from '../components/AccessDeniedModal';

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

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [checkingGate, setCheckingGate] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Policy check modal state
  const [showDeniedModal, setShowDeniedModal] = useState(false);
  const [deniedInfo, setDeniedInfo] = useState<{
    reason: string;
    details?: PolicyCheckResponse['details'];
  }>({ reason: '' });
  const [retrying, setRetrying] = useState(false);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const data = await profileApi.getProfile();
        setProfile(data);

        // If policy not set, redirect to policy page
        if (!data.hasPolicy) {
          navigate('/working-policy');
        }
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load security profile');
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [navigate]);

  const handleContinueToWallet = async () => {
    try {
      setCheckingGate(true);
      setError(null);
      const coords = await getCurrentCoordinates();
      const checkRes = await walletApi.checkAccess(coords.lat, coords.lng);

      if (checkRes.allowed) {
        navigate('/wallet');
      } else {
        setDeniedInfo({
          reason: checkRes.reason,
          details: checkRes.details,
        });
        setShowDeniedModal(true);
      }
    } catch (err: any) {
      setDeniedInfo({
        reason: err.response?.data?.error || 'Failed to verify policy gate before opening wallet',
      });
      setShowDeniedModal(true);
    } finally {
      setCheckingGate(false);
    }
  };

  const handleRetry = async () => {
    try {
      setRetrying(true);
      const coords = await getCurrentCoordinates();
      const checkRes = await walletApi.checkAccess(coords.lat, coords.lng);

      if (checkRes.allowed) {
        setShowDeniedModal(false);
        navigate('/wallet');
      } else {
        setDeniedInfo({
          reason: checkRes.reason,
          details: checkRes.details,
        });
      }
    } catch (err: any) {
      setDeniedInfo({
        reason: err.response?.data?.error || 'Policy verification failed on retry.',
      });
    } finally {
      setRetrying(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <p style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Loading security profile...</p>
      </div>
    );
  }

  const { user, policy, mfa } = profile || {};

  return (
    <>
      <div className="card">
        <h1 className="page-title">Security Review</h1>
        <p className="page-subtitle">Summary of your authenticated session and working policy</p>

        {error && <div className="alert alert-danger">{error}</div>}

        <div className="summary-list">
          <div className="summary-item">
            <span className="summary-label">Login Method</span>
            <span className="summary-value">
              {user?.login_method === 'google' ? `Google (${user?.email || 'Authenticated'})` : `Mobile (${user?.mobile || 'Verified'})`}
            </span>
          </div>

          <div className="summary-item">
            <span className="summary-label">MFA Status</span>
            <span className="summary-value" style={{ color: 'var(--success)' }}>
              Verified ({mfa?.type ? mfa.type.toUpperCase() : 'OTP'})
            </span>
          </div>

          <div className="summary-item">
            <span className="summary-label">Working Time</span>
            <span className="summary-value">
              {policy?.start_time} — {policy?.end_time} ({policy?.timezone})
            </span>
          </div>

          <div className="summary-item">
            <span className="summary-label">Working Location</span>
            <span className="summary-value">
              {policy?.city} ({policy?.radius_km} km radius)
            </span>
          </div>

          <div className="summary-item">
            <span className="summary-label">Coordinates</span>
            <span className="summary-value text-mono" style={{ fontSize: '12px' }}>
              {policy?.lat?.toFixed(4)}, {policy?.lng?.toFixed(4)}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
          <button
            type="button"
            className="btn btn-outline"
            onClick={() => navigate('/working-policy')}
          >
            Change Policy
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={handleContinueToWallet}
            disabled={checkingGate}
          >
            {checkingGate ? 'Verifying Working Hours & Location...' : 'Continue to Wallet'}
          </button>
        </div>
      </div>

      <AccessDeniedModal
        isOpen={showDeniedModal}
        reason={deniedInfo.reason}
        details={deniedInfo.details}
        onRetry={handleRetry}
        onLogout={logout}
        retrying={retrying}
      />
    </>
  );
};
