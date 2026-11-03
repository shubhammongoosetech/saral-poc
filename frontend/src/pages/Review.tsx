import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi } from '../api/endpoints';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  if (loading) {
    return (
      <div className="card">
        <p style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Loading security profile...</p>
      </div>
    );
  }

  const { user, policy, mfa } = profile || {};

  return (
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
          onClick={() => navigate('/wallet')}
        >
          Continue to Wallet
        </button>
      </div>
    </div>
  );
};
