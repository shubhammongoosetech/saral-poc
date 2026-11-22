import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi, walletApi } from '@/shared/api/endpoints';
import { ProfileResponse } from '@/shared/api/types';
import { useSession } from '@/features/auth/useSession';
import { mapApiError } from '@/shared/lib/format';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { Button } from '@/shared/ui/Button';
import { Card } from '@/shared/ui/Card';
import { Alert } from '@/shared/ui/Alert';
import { Skeleton } from '@/shared/ui/Skeleton';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const { setLastAccessCheck } = useSession();

  const [profile, setProfile] = useState<ProfileResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const data = await profileApi.getProfile();
        if (!active) return;
        setProfile(data);
        if (!data.hasPolicy) {
          navigate('/working-policy', { replace: true });
        }
      } catch (err: unknown) {
        if (active) setError(mapApiError(err, 'Failed to load details'));
      } finally {
        if (active) setLoading(false);
      }
    };

    fetchProfile();
    return () => {
      active = false;
    };
  }, [navigate]);

  const handleConfirm = async () => {
    try {
      setConfirming(true);
      setError(null);
      const res = await walletApi.checkAccess();
      setLastAccessCheck(res);

      if (res.allowed) {
        navigate('/wallet');
      } else {
        setError(res.reason || 'Access denied outside working hours or location');
      }
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to verify access'));
    } finally {
      setConfirming(false);
    }
  };

  if (loading) {
    return (
      <AuthLayout>
        <div className="w-full flex flex-col gap-4">
          <Skeleton className="h-7 w-24 mx-auto" />
          <Skeleton className="h-44 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </AuthLayout>
    );
  }

  const user = profile?.user;
  const policy = profile?.policy;

  const hours = policy
    ? `${policy.startTime || policy.start_time || '09:00'} - ${policy.endTime || policy.end_time || '18:00'}`
    : 'None';
  const city = policy?.city || 'None';
  const radius = policy?.radiusKm ? `${policy.radiusKm} km` : '25 km';
  const timezone = policy?.timezone || 'Asia/Kolkata';

  return (
    <AuthLayout>
      <div className="w-full flex flex-col gap-5">
        <h1 className="text-xl font-semibold text-text text-center tracking-tight">Review</h1>

        {error && <Alert variant="error">{error}</Alert>}

        <Card className="divide-y divide-border p-0 overflow-hidden">
          {user?.email && (
            <div className="flex justify-between items-center py-2.5 px-4 text-xs">
              <span className="text-muted font-medium">Email</span>
              <span className="text-text font-mono truncate max-w-[200px]">{user.email}</span>
            </div>
          )}
          {user?.mobile && (
            <div className="flex justify-between items-center py-2.5 px-4 text-xs">
              <span className="text-muted font-medium">Mobile</span>
              <span className="text-text font-mono">{user.mobile}</span>
            </div>
          )}
          <div className="flex justify-between items-center py-2.5 px-4 text-xs">
            <span className="text-muted font-medium">Hours</span>
            <span className="text-text font-mono">{hours}</span>
          </div>
          <div className="flex justify-between items-center py-2.5 px-4 text-xs">
            <span className="text-muted font-medium">City</span>
            <span className="text-text">{city}</span>
          </div>
          <div className="flex justify-between items-center py-2.5 px-4 text-xs">
            <span className="text-muted font-medium">Radius</span>
            <span className="text-text font-mono">{radius}</span>
          </div>
          <div className="flex justify-between items-center py-2.5 px-4 text-xs">
            <span className="text-muted font-medium">Timezone</span>
            <span className="text-text font-mono truncate max-w-[180px]">{timezone}</span>
          </div>
        </Card>

        <div className="flex gap-2">
          <Button
            type="button"
            variant="secondary"
            onClick={() => navigate('/working-policy')}
            disabled={confirming}
            className="flex-1"
          >
            Edit
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={handleConfirm}
            loading={confirming}
            className="flex-1"
          >
            Confirm
          </Button>
        </div>
      </div>
    </AuthLayout>
  );
};

export default Review;
