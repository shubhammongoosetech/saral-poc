import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi, walletApi } from '../api/endpoints';
import { getCurrentCoords } from '../hooks/useLocation';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const data = await profileApi.getProfile();
        setProfile(data);
        if (!data.hasPolicy) {
          navigate('/working-policy');
        }
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load details');
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [navigate]);

  const handleConfirm = async () => {
    try {
      setConfirming(true);
      setError(null);
      const coords = await getCurrentCoords();
      const res = await walletApi.checkAccess(coords.lat, coords.lng);
      if (res.allowed) {
        navigate('/wallet');
      } else {
        setError(
          res.reason
            ? `Access blocked: ${res.reason}`
            : 'Access allowed only during your working time and location.'
        );
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to confirm');
    } finally {
      setConfirming(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <p className="muted text-center">Loading...</p>
      </div>
    );
  }

  const user = profile?.user;
  const policy = profile?.policy;

  const loginMethodText =
    user?.login_method === 'google'
      ? `Google (${user?.email || 'Connected'})`
      : `Mobile (${user?.mobile || 'Verified'})`;

  const workingHoursText = policy
    ? `${policy.start_time || policy.startTime} - ${policy.end_time || policy.endTime}`
    : 'Not configured';

  const locationText = policy?.city || 'Not configured';

  return (
    <div className="card">
      <h1 className="page-title">Confirm</h1>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="two-column-list">
        {user?.name && (
          <div className="two-column-item">
            <span className="label-col">Name</span>
            <span className="value-col">{user.name}</span>
          </div>
        )}
        {user?.email && (
          <div className="two-column-item">
            <span className="label-col">Email</span>
            <span className="value-col">{user.email}</span>
          </div>
        )}
        {user?.mobile && (
          <div className="two-column-item">
            <span className="label-col">Mobile</span>
            <span className="value-col">{user.mobile}</span>
          </div>
        )}
        <div className="two-column-item">
          <span className="label-col">Login method</span>
          <span className="value-col">{user?.login_method === 'google' ? 'Google' : 'Mobile'}</span>
        </div>
        <div className="two-column-item">
          <span className="label-col">Two-step</span>
          <span className="value-col">Verified</span>
        </div>
        <div className="two-column-item">
          <span className="label-col">Working hours</span>
          <span className="value-col">{workingHoursText}</span>
        </div>
        <div className="two-column-item">
          <span className="label-col">Location</span>
          <span className="value-col">{locationText}</span>
        </div>
      </div>

      <button
        type="button"
        className="btn btn-primary"
        onClick={handleConfirm}
        disabled={confirming}
      >
        {confirming ? 'Confirming...' : 'Confirm'}
      </button>
    </div>
  );
};
