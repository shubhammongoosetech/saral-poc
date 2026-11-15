import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSession } from '@/features/auth/useSession';
import { useTheme } from '@/shared/hooks/useTheme';
import { useBreakpoint } from '@/shared/hooks/useBreakpoint';
import { profileApi } from '@/shared/api/endpoints';
import { ProfileResponse } from '@/shared/api/types';
import { Card } from '@/shared/ui/Card';
import { Button } from '@/shared/ui/Button';
import { Skeleton } from '@/shared/ui/Skeleton';
import { formatRelativeTime } from '@/shared/lib/format';

type SettingsTab = 'account' | 'policy' | 'advanced';

export const Settings: React.FC = () => {
  const navigate = useNavigate();
  const { logout } = useSession();
  const { theme, setTheme } = useTheme();
  const { isDesktop } = useBreakpoint();

  const [activeTab, setActiveTab] = useState<SettingsTab>('account');
  const [profile, setProfile] = useState<ProfileResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    profileApi
      .getProfile()
      .then((data) => {
        if (active) setProfile(data);
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto">
        <Skeleton className="h-8 w-32" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  const user = profile?.user;
  const policy = profile?.policy;
  const hours = policy
    ? `${policy.startTime || policy.start_time || '09:00'} - ${policy.endTime || policy.end_time || '18:00'}`
    : 'None';
  const city = policy?.city || 'None';
  const radius = policy?.radiusKm ? `${policy.radiusKm} km` : '25 km';
  const policySetAt = policy?.setAt || policy?.set_at;

  const renderContent = () => {
    switch (activeTab) {
      case 'account':
        return (
          <div className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold text-text">Account</h2>
            <Card className="divide-y divide-border p-0 overflow-hidden text-xs">
              {user?.email && (
                <div className="flex justify-between items-center p-3.5">
                  <span className="text-muted font-medium">Email</span>
                  <span className="text-text font-mono">{user.email}</span>
                </div>
              )}
              {user?.mobile && (
                <div className="flex justify-between items-center p-3.5">
                  <span className="text-muted font-medium">Mobile</span>
                  <span className="text-text font-mono">{user.mobile}</span>
                </div>
              )}
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">Theme</span>
                <div className="inline-flex p-0.5 rounded-full bg-surface-2 border border-border">
                  <button
                    type="button"
                    onClick={() => setTheme('light')}
                    className={`px-2.5 py-0.5 rounded-full text-xs font-medium transition-colors ${
                      theme === 'light' ? 'bg-surface text-text shadow-xs' : 'text-muted'
                    }`}
                  >
                    Light
                  </button>
                  <button
                    type="button"
                    onClick={() => setTheme('dark')}
                    className={`px-2.5 py-0.5 rounded-full text-xs font-medium transition-colors ${
                      theme === 'dark' ? 'bg-surface text-text shadow-xs' : 'text-muted'
                    }`}
                  >
                    Dark
                  </button>
                </div>
              </div>
            </Card>

            <Button variant="danger" onClick={() => logout()} className="self-start">
              Log out
            </Button>
          </div>
        );

      case 'policy':
        return (
          <div className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold text-text">Working hours</h2>
            <Card className="divide-y divide-border p-0 overflow-hidden text-xs">
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">Hours</span>
                <span className="font-mono text-text">{hours}</span>
              </div>
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">City</span>
                <span className="text-text">{city}</span>
              </div>
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">Radius</span>
                <span className="font-mono text-text">{radius}</span>
              </div>
            </Card>

            <Button
              variant="secondary"
              onClick={() => navigate('/working-policy')}
              className="self-start"
            >
              Edit policy
            </Button>
          </div>
        );

      case 'advanced':
        return (
          <div className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold text-text">Advanced</h2>
            <Card className="divide-y divide-border p-0 overflow-hidden text-xs">
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">MFA</span>
                <span className="text-text font-medium">{profile?.mfa?.type || 'otp'}</span>
              </div>
              <div className="flex justify-between items-center p-3.5">
                <span className="text-muted font-medium">MFA verified</span>
                <span className="text-text font-medium">
                  {profile?.mfaVerified ? 'Verified' : 'Unverified'}
                </span>
              </div>
              {policySetAt && (
                <div className="flex justify-between items-center p-3.5">
                  <span className="text-muted font-medium">Policy updated</span>
                  <span className="text-text font-mono">{formatRelativeTime(policySetAt)}</span>
                </div>
              )}
            </Card>
          </div>
        );
    }
  };

  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'account', label: 'Account' },
    { id: 'policy', label: 'Working hours' },
    { id: 'advanced', label: 'Advanced' },
  ];

  return (
    <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto">
      <h1 className="text-xl font-semibold text-text">Settings</h1>

      {isDesktop ? (
        <div className="grid grid-cols-12 gap-8">
          <div className="col-span-3 flex flex-col gap-1">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`text-left px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-surface text-text font-semibold border border-border shadow-xs'
                      : 'text-muted hover:text-text hover:bg-surface-2'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="col-span-9">{renderContent()}</div>
        </div>
      ) : (
        <div className="flex flex-col gap-5">
          <div className="flex p-1 rounded-lg bg-surface-2 border border-border">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 py-1.5 text-center text-xs font-medium rounded-md transition-colors ${
                    isActive
                      ? 'bg-surface text-text shadow-xs font-semibold'
                      : 'text-muted hover:text-text'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div>{renderContent()}</div>
        </div>
      )}
    </div>
  );
};

export default Settings;
