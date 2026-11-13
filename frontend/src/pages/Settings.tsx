import React, { useState, useEffect } from 'react';
import { apiClient as api } from '../api/client';
import { AccountSection } from './Settings/AccountSection';
import { WorkingHoursSection } from './Settings/WorkingHoursSection';
import { AdvancedSection } from './Settings/AdvancedSection';

export const Settings: React.FC = () => {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        setError(null);
        const res = await api.get('/profile');
        setProfile(res.data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load settings');
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, []);

  if (loading) {
    return (
      <div className="card card-wide">
        <p className="muted text-center">Loading settings...</p>
      </div>
    );
  }

  return (
    <div className="card card-wide">
      <h1 className="page-title">Settings</h1>

      {error && <div className="alert alert-error">{error}</div>}

      <AccountSection user={profile?.user} />

      <WorkingHoursSection initialPolicy={profile?.policy} />

      <AdvancedSection />
    </div>
  );
};
